"""
Packet parsing for NetScope.

Reads a PCAP or PCAPNG capture file with Scapy and converts every packet into
a small metadata record (a plain dictionary). The list of records is then
turned into a pandas DataFrame that the rest of the application uses.

Only header metadata is extracted (addresses, ports, lengths, flags, DNS query
name). Application payload bytes are never stored or displayed.
"""

from __future__ import annotations

import logging
import os
from datetime import datetime
from typing import Any

# Scapy prints a warning about libpcap on Windows. We only read files offline,
# so libpcap/Npcap is not needed; silence that warning before importing Scapy.
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

import pandas as pd  # noqa: E402
from scapy.layers.dns import dnstypes  # noqa: E402
from scapy.layers.inet import ICMP, IP, TCP, UDP  # noqa: E402
from scapy.layers.inet6 import IPv6, _ICMPv6, icmp6types  # noqa: E402
from scapy.layers.l2 import ARP, Ether  # noqa: E402
from scapy.layers.inet import icmptypes  # noqa: E402
from scapy.packet import Packet  # noqa: E402
from scapy.utils import PcapReader  # noqa: E402

from netscope import protocol_analyzer as pa  # noqa: E402

# Magic numbers at the start of capture files (first 4 bytes).
PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1",  # pcap, little-endian, microsecond timestamps
    b"\xa1\xb2\xc3\xd4",  # pcap, big-endian, microsecond timestamps
    b"\x4d\x3c\xb2\xa1",  # pcap, little-endian, nanosecond timestamps
    b"\xa1\xb2\x3c\x4d",  # pcap, big-endian, nanosecond timestamps
}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"  # pcapng Section Header Block type

# Column order of the packet DataFrame (the "packet metadata model").
COLUMNS = [
    "packet_no",            # 1-based position in the capture file
    "timestamp",            # capture time, seconds since 1970 (float)
    "time",                 # capture time, human readable (local time)
    "relative_time",        # seconds since the first packet
    "src_mac", "dst_mac",   # Ethernet (layer 2) addresses, if present
    "src_ip", "dst_ip",     # IPv4 / IPv6 addresses (or ARP sender/target IP)
    "network_protocol",     # IPv4 / IPv6 / ARP / Other
    "transport_protocol",   # TCP / UDP / ICMP / ICMPv6 / Not Applicable / Other
    "application_protocol", # DNS / Other
    "protocol",             # most specific of the three, for the table
    "src_port", "dst_port", # TCP / UDP ports only
    "length",               # captured length in bytes
    "tcp_flags", "tcp_seq", "tcp_ack",
    "icmp_type", "icmp_code", "icmp_info",
    "arp_operation",
    "dns_query", "dns_query_type", "dns_direction",
    "parse_error",          # set if this packet could not be fully decoded
]

TCP_FLAG_NAMES = [
    ("F", "FIN"), ("S", "SYN"), ("R", "RST"), ("P", "PSH"),
    ("A", "ACK"), ("U", "URG"), ("E", "ECE"), ("C", "CWR"),
]


class CaptureFileError(Exception):
    """Raised when a capture file is empty, invalid or cannot be read."""


# ---------------------------------------------------------------------------
# File validation
# ---------------------------------------------------------------------------
def detect_format(path: str) -> str:
    """Return 'pcap' or 'pcapng' based on the file's magic number.

    Raises CaptureFileError for empty files or files that are not captures.
    """
    if not os.path.exists(path):
        raise CaptureFileError("The capture file could not be found.")
    if os.path.getsize(path) == 0:
        raise CaptureFileError("The uploaded file is empty (0 bytes).")
    with open(path, "rb") as f:
        magic = f.read(4)
    if magic in PCAP_MAGICS:
        return "pcap"
    if magic == PCAPNG_MAGIC:
        return "pcapng"
    raise CaptureFileError(
        "This file is not a valid PCAP or PCAPNG capture. "
        "Save the capture from Wireshark using File > Save As (pcap or pcapng)."
    )


def is_truncated(path: str, file_format: str) -> bool:
    """Check whether the capture file ends in the middle of a packet.

    Scapy quietly ignores (pcapng) or shortens (pcap) a final packet that was
    cut off, so we walk the file structure ourselves:
      * pcap:   24-byte global header, then per packet a 16-byte record
                header whose 'incl_len' field (offset 8) gives the data length.
      * pcapng: a sequence of blocks; bytes 4-8 of every block hold its
                total length. The byte order is set by each Section Header Block.
    """
    import struct

    with open(path, "rb") as f:
        data = f.read()
    size = len(data)

    if file_format == "pcap":
        endian = "<" if data[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
        pos = 24
        if size < pos:
            return True
        while pos < size:
            if pos + 16 > size:
                return True
            (incl_len,) = struct.unpack(endian + "I", data[pos + 8:pos + 12])
            pos += 16 + incl_len
        return pos != size

    # pcapng
    pos, endian = 0, "<"
    while pos < size:
        if pos + 12 > size:
            return True
        if data[pos:pos + 4] == PCAPNG_MAGIC:  # Section Header Block: read byte order
            endian = "<" if data[pos + 8:pos + 12] == b"\x4d\x3c\x2b\x1a" else ">"
        (block_len,) = struct.unpack(endian + "I", data[pos + 4:pos + 8])
        if block_len < 12:
            return True
        pos += block_len
    return pos != size


# ---------------------------------------------------------------------------
# Per-packet metadata extraction
# ---------------------------------------------------------------------------
def format_tcp_flags(flags: Any) -> str:
    """Convert Scapy's flag string (e.g. 'SA') into 'SYN, ACK'."""
    text = str(flags)
    names = [name for letter, name in TCP_FLAG_NAMES if letter in text]
    return ", ".join(names)


def _empty_record(packet_no: int) -> dict[str, Any]:
    record = {col: None for col in COLUMNS}
    record["packet_no"] = packet_no
    return record


def _captured_length(pkt: Packet) -> int:
    """Captured length = number of bytes Wireshark saved for this packet."""
    original = getattr(pkt, "original", None)
    if original is not None:
        return len(original)
    return len(bytes(pkt))


def extract_metadata(pkt: Packet, packet_no: int) -> dict[str, Any]:
    """Build one metadata record from one Scapy packet.

    This function never raises: if a field cannot be decoded, the packet is
    still returned (so every packet is counted exactly once) and the problem
    is noted in the 'parse_error' column.
    """
    record = _empty_record(packet_no)

    # --- Basic information that every packet has -------------------------
    try:
        record["timestamp"] = float(pkt.time)
        record["time"] = datetime.fromtimestamp(record["timestamp"]).strftime(
            "%Y-%m-%d %H:%M:%S.%f"
        )
    except Exception:
        record["parse_error"] = "Invalid timestamp"
    try:
        record["length"] = _captured_length(pkt)
    except Exception:
        record["length"] = 0
        record["parse_error"] = "Could not determine packet length"

    try:
        # --- Layer 2: Ethernet MAC addresses ------------------------------
        if Ether in pkt:
            record["src_mac"] = pkt[Ether].src
            record["dst_mac"] = pkt[Ether].dst

        # --- Layer 3: network protocol and IP addresses -------------------
        network = pa.classify_network(pkt)
        net_layer = pa.find_network_layer(pkt)
        if network in ("IPv4", "IPv6"):
            record["src_ip"] = net_layer.src
            record["dst_ip"] = net_layer.dst
        elif network == "ARP":
            # ARP has no IP header. Its body contains the sender and target
            # IP addresses, which we show as source / destination IP.
            record["src_ip"] = net_layer.psrc
            record["dst_ip"] = net_layer.pdst
            record["arp_operation"] = {1: "Request (who-has)", 2: "Reply (is-at)"}.get(
                int(net_layer.op), f"Operation {net_layer.op}"
            )

        # --- Layer 4: transport protocol, ports, flags --------------------
        transport = pa.classify_transport(pkt)
        trans_layer = pa.find_transport_layer(pkt)
        if transport in ("TCP", "UDP"):
            record["src_port"] = int(trans_layer.sport)
            record["dst_port"] = int(trans_layer.dport)
        if transport == "TCP":
            record["tcp_flags"] = format_tcp_flags(trans_layer.flags)
            record["tcp_seq"] = int(trans_layer.seq)
            record["tcp_ack"] = int(trans_layer.ack)
        elif transport == "ICMP":
            record["icmp_type"] = int(trans_layer.type)
            record["icmp_code"] = int(trans_layer.code)
            record["icmp_info"] = icmptypes.get(record["icmp_type"], "Unknown")
        elif transport == "ICMPv6":
            record["icmp_type"] = int(trans_layer.type)
            record["icmp_code"] = int(getattr(trans_layer, "code", 0) or 0)
            record["icmp_info"] = icmp6types.get(record["icmp_type"], "Unknown")

        # --- Layer 7: application protocol (DNS only) ---------------------
        application = pa.classify_application(pkt)
        if application == "DNS":
            dns = pa.get_dns_layer(pkt)
            record["dns_direction"] = "Response" if dns.qr == 1 else "Query"
            if dns.qd:
                question = dns.qd[0]
                qname = question.qname
                if isinstance(qname, bytes):
                    qname = qname.decode("utf-8", errors="replace")
                record["dns_query"] = qname.rstrip(".") or "."
                record["dns_query_type"] = dnstypes.get(question.qtype, str(question.qtype))

        record["network_protocol"] = network
        record["transport_protocol"] = transport
        record["application_protocol"] = application
        record["protocol"] = pa.display_protocol(network, transport, application)

    except Exception as exc:  # malformed packet: keep it, mark it
        record["network_protocol"] = record["network_protocol"] or pa.OTHER
        record["transport_protocol"] = record["transport_protocol"] or pa.OTHER
        record["application_protocol"] = record["application_protocol"] or pa.OTHER
        record["protocol"] = pa.OTHER
        record["parse_error"] = f"Malformed packet: {type(exc).__name__}"

    return record


# ---------------------------------------------------------------------------
# Whole-file parsing
# ---------------------------------------------------------------------------
def records_to_dataframe(records: list[dict[str, Any]]) -> pd.DataFrame:
    """Convert records to a DataFrame with proper column types."""
    df = pd.DataFrame(records, columns=COLUMNS)
    # Nullable integers so that "no port" shows as empty instead of NaN/float.
    for col in ["src_port", "dst_port", "tcp_seq", "tcp_ack", "icmp_type", "icmp_code"]:
        df[col] = df[col].astype("Int64")
    df["length"] = df["length"].fillna(0).astype(int)
    if len(df) and df["timestamp"].notna().any():
        df["relative_time"] = (df["timestamp"] - df["timestamp"].min()).round(6)
    return df


def parse_capture(path: str) -> tuple[pd.DataFrame, dict[str, Any]]:
    """Parse a PCAP/PCAPNG file into a packet DataFrame.

    Returns (dataframe, info) where info contains the file format, packet
    count and any warning (e.g. a truncated file).

    Raises CaptureFileError if the file is empty, not a capture file, or
    contains no packets at all.
    """
    file_format = detect_format(path)
    records: list[dict[str, Any]] = []
    warning = None

    try:
        # PcapReader automatically detects pcap vs pcapng and reads packets
        # one at a time (streaming), so large files do not need to fit in a list.
        with PcapReader(path) as reader:
            for pkt in reader:
                records.append(extract_metadata(pkt, len(records) + 1))
    except CaptureFileError:
        raise
    except Exception as exc:
        if not records:
            raise CaptureFileError(
                f"The capture file could not be read ({type(exc).__name__}). "
                "It may be corrupted or truncated."
            ) from exc
        # Some packets were read before the error, e.g. a capture that was
        # cut off while saving. Keep what was read and warn the user.
        warning = (
            f"The file appears to be truncated or corrupted after packet "
            f"{len(records)}. Only the first {len(records)} packets were analyzed."
        )

    if not records:
        raise CaptureFileError("The capture file is valid but contains no packets.")

    if warning is None and is_truncated(path, file_format):
        warning = (
            "The capture file ends in the middle of a packet (it may have been "
            f"cut off while saving). {len(records)} complete or partial packets "
            "were analyzed; the incomplete final packet may be missing or shortened."
        )

    info = {
        "format": file_format,
        "packet_count": len(records),
        "warning": warning,
        "malformed_count": sum(1 for r in records if r["parse_error"]),
    }
    return records_to_dataframe(records), info
