"""
Protocol classification for NetScope.

Every packet is classified at three separate layers of the TCP/IP model:

    Network layer      -> IPv4, IPv6, ARP, or "Other / Not Detected"
    Transport layer    -> TCP, UDP, ICMP, ICMPv6, "Not Applicable" (ARP),
                          or "Other / Not Detected"
    Application layer  -> DNS, HTTP, TLS, or "Other / Not Detected"

The three classifications are independent. A DNS query is counted once in
each layer's distribution (IPv4 / UDP / DNS), never three times in one chart.

Classification is based on the packet bytes, NOT on port numbers alone. For
example, a packet on port 443 is not assumed to be TLS, and a packet on port 53
is only DNS if Scapy was able to decode a well-formed DNS header from it. HTTP
and TLS are detected by reading the start of the TCP payload and checking that
it is a valid HTTP request/status line or TLS record header (see parse_http and
parse_tls below). Only these headers are read; the payload itself is never kept.
"""

from __future__ import annotations

import re
from collections import Counter
from typing import Iterable, Mapping

import pandas as pd
from scapy.layers.dns import DNS
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6, _ICMPv6
from scapy.layers.l2 import ARP
from scapy.packet import Packet, Padding

# ---------------------------------------------------------------------------
# Category labels (kept in one place so every module uses the same strings)
# ---------------------------------------------------------------------------
OTHER = "Other / Not Detected"
NOT_APPLICABLE = "Not Applicable"

NETWORK_PROTOCOLS = ["IPv4", "IPv6", "ARP"]
TRANSPORT_PROTOCOLS = ["TCP", "UDP", "ICMP", "ICMPv6"]
APPLICATION_PROTOCOLS = ["DNS", "HTTP", "TLS"]

# Full ordered category lists, used so charts also show categories with 0 packets.
NETWORK_CATEGORIES = NETWORK_PROTOCOLS + [OTHER]
TRANSPORT_CATEGORIES = TRANSPORT_PROTOCOLS + [NOT_APPLICABLE, OTHER]
APPLICATION_CATEGORIES = APPLICATION_PROTOCOLS + [OTHER]


def _iter_layers(pkt: Packet) -> Iterable[Packet]:
    """Yield each decoded layer of a packet, outermost first (Ether, IP, TCP...)."""
    layer = pkt
    # Scapy marks the end of the layer chain with NoPayload, which is falsy.
    while layer:
        yield layer
        layer = layer.payload


def find_network_layer(pkt: Packet) -> Packet | None:
    """Return the OUTERMOST IPv4 / IPv6 / ARP layer, or None.

    We take the first one found because ICMP error messages carry a copy of
    the original (inner) IP header, which must not be mistaken for the real one.
    """
    for layer in _iter_layers(pkt):
        if isinstance(layer, (IP, IPv6, ARP)):
            return layer
    return None


def find_transport_layer(pkt: Packet) -> Packet | None:
    """Return the first TCP / UDP / ICMP / ICMPv6 layer after the network layer.

    Walking the layers in order matters: an ICMP "Destination Unreachable"
    message contains a quoted UDP header (UDPerror). The first transport layer
    we meet is ICMP, which is the correct answer.
    """
    for layer in _iter_layers(pkt):
        if isinstance(layer, (TCP, UDP, ICMP, _ICMPv6)):
            return layer
    return None


def classify_network(pkt: Packet) -> str:
    """Classify the network (Internet) layer protocol."""
    layer = find_network_layer(pkt)
    if isinstance(layer, ARP):
        return "ARP"
    if isinstance(layer, IPv6):  # check IPv6 before IP: they are separate classes
        return "IPv6"
    if isinstance(layer, IP):
        return "IPv4"
    return OTHER


def classify_transport(pkt: Packet) -> str:
    """Classify the transport layer protocol.

    ARP works directly over Ethernet, so it has no transport layer at all.
    An IP packet carrying something else (e.g. IGMP, GRE, or a non-first IP
    fragment that cannot be decoded) is reported as Other / Not Detected.
    """
    network = classify_network(pkt)
    if network == "ARP":
        return NOT_APPLICABLE

    layer = find_transport_layer(pkt)
    if layer is None:
        return OTHER
    if isinstance(layer, _ICMPv6):
        return "ICMPv6"
    if isinstance(layer, ICMP):
        return "ICMP"
    if isinstance(layer, TCP):
        return "TCP"
    if isinstance(layer, UDP):
        return "UDP"
    return OTHER


def get_dns_layer(pkt: Packet) -> DNS | None:
    """Return the DNS layer only if Scapy decoded a plausible DNS message.

    Scapy tries to decode traffic on port 53 (and mDNS port 5353) as DNS.
    We add a sanity check so random bytes on port 53 are not counted as DNS:
    the opcode must be a defined value and the number of decoded questions
    must match the question count in the header.
    """
    dns = pkt.getlayer(DNS)
    if dns is None:
        return None
    try:
        if dns.opcode not in (0, 1, 2, 4, 5, 6):
            return None
        questions = dns.qd or []
        if dns.qdcount is not None and dns.qdcount != len(questions):
            return None
    except Exception:  # malformed DNS fields
        return None
    return dns


# ---------------------------------------------------------------------------
# HTTP and TLS: parsed from the start of the TCP payload
# ---------------------------------------------------------------------------
HTTP_METHODS = ("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE")
_HTTP_REQUEST_LINE = re.compile(
    rb"^(" + b"|".join(m.encode() for m in HTTP_METHODS) + rb") (\S+) HTTP/1\.[01]\r?$"
)
_HTTP_STATUS_LINE = re.compile(rb"^HTTP/1\.[01] ([1-5]\d\d)(?: ([^\r\n]*))?\r?$")

TLS_VERSIONS = {0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1",
                0x0303: "TLS 1.2", 0x0304: "TLS 1.3"}
TLS_CONTENT_TYPES = {20: "Change Cipher Spec", 21: "Alert", 22: "Handshake", 23: "Application Data"}
TLS_HANDSHAKE_TYPES = {
    0: "Hello Request", 1: "Client Hello", 2: "Server Hello", 4: "New Session Ticket",
    8: "Encrypted Extensions", 11: "Certificate", 12: "Server Key Exchange",
    13: "Certificate Request", 14: "Server Hello Done", 15: "Certificate Verify",
    16: "Client Key Exchange", 20: "Finished",
}
_TLS_MAX_RECORD = 2**14 + 2048  # largest legal TLSCiphertext length (RFC 5246)


def tcp_payload(pkt: Packet) -> bytes:
    """Bytes carried by the TCP segment, without any Ethernet padding."""
    tcp = pkt.getlayer(TCP)
    if tcp is None:
        return b""
    data = bytes(tcp.payload)
    pad = tcp.getlayer(Padding)
    if pad is not None:
        data = data[: len(data) - len(bytes(pad))]
    return data


def parse_http(payload: bytes) -> dict | None:
    """Parse an HTTP/1.x request line or status line, plus the Host header.

    Returns None unless the first line is well formed, e.g.
    'GET /index.html HTTP/1.1' or 'HTTP/1.1 200 OK'. The message body is ignored.
    """
    if not payload:
        return None
    first, _, rest = payload.partition(b"\n")
    request = _HTTP_REQUEST_LINE.match(first)
    if request:
        host = None
        for line in rest.split(b"\n"):
            line = line.rstrip(b"\r")
            if not line:  # blank line = end of the headers
                break
            name, sep, value = line.partition(b":")
            if sep and name.strip().lower() == b"host":
                host = value.strip().decode("ascii", errors="replace")
                break
        return {
            "kind": "Request",
            "method": request.group(1).decode(),
            "uri": request.group(2).decode("ascii", errors="replace")[:200],
            "host": host,
        }
    status = _HTTP_STATUS_LINE.match(first)
    if status:
        reason = (status.group(2) or b"").decode("ascii", errors="replace").strip()
        return {"kind": "Response", "status": f"{status.group(1).decode()} {reason}".strip()}
    return None


def _tls_version_name(value: int) -> str:
    return TLS_VERSIONS.get(value, f"0x{value:04x}")


def _is_grease(value: int) -> bool:
    """GREASE values (RFC 8701) such as 0x0a0a are placeholders, not real versions."""
    return (value & 0x0F0F) == 0x0A0A and (value >> 8) == (value & 0xFF)


def _parse_hello(body: bytes, client: bool) -> dict:
    """Read the TLS version and, for a Client Hello, the SNI host name.

    Hello layout (RFC 8446 section 4.1.2 / 4.1.3): version(2) random(32)
    session_id<0..32> cipher_suite(s) compression_method(s) extensions<..>.
    The real version of TLS 1.3 is in the supported_versions extension (43);
    the server name is in the server_name extension (0, RFC 6066).
    """
    if len(body) < 35:
        return {}
    version = int.from_bytes(body[0:2], "big")
    info: dict = {}
    pos = 34
    pos += 1 + body[pos]                                     # session id
    if client:
        if pos + 2 > len(body):
            return {"version": _tls_version_name(version)}
        pos += 2 + int.from_bytes(body[pos:pos + 2], "big")  # cipher suites
        if pos >= len(body):
            return {"version": _tls_version_name(version)}
        pos += 1 + body[pos]                                 # compression methods
    else:
        pos += 3                                             # one suite + one method
    if pos + 2 <= len(body):
        end = min(len(body), pos + 2 + int.from_bytes(body[pos:pos + 2], "big"))
        pos += 2
        while pos + 4 <= end:
            ext_type = int.from_bytes(body[pos:pos + 2], "big")
            ext_len = int.from_bytes(body[pos + 2:pos + 4], "big")
            ext = body[pos + 4:pos + 4 + ext_len]
            pos += 4 + ext_len
            if ext_type == 0 and client and len(ext) >= 5 and ext[2] == 0:   # server_name
                name_len = int.from_bytes(ext[3:5], "big")
                if 5 + name_len <= len(ext):
                    info["sni"] = ext[5:5 + name_len].decode("ascii", errors="replace")
            elif ext_type == 43:                                             # supported_versions
                if client and ext:
                    offered = [int.from_bytes(ext[i:i + 2], "big")
                               for i in range(1, min(len(ext) - 1, 1 + ext[0]), 2)]
                    offered = [v for v in offered if not _is_grease(v)]
                    if offered:
                        version = max(offered)
                elif not client and len(ext) == 2:
                    version = int.from_bytes(ext, "big")
    info["version"] = _tls_version_name(version)
    return info


def parse_tls(payload: bytes) -> dict | None:
    """Parse the TLS record headers at the start of a TCP payload.

    Every TLS record starts with a 5-byte header: content type (20-23),
    protocol version (major 3, minor 0-4) and a 2-byte length. Returns None if
    the payload does not start with such a header. When one segment carries
    several records they are listed in order, e.g. 'Server Hello, Certificate'.

    The version is taken from a Client/Server Hello when one is present (this
    is the version offered/chosen, including TLS 1.3). Otherwise only the record
    header version is known, which TLS 1.3 always sets to 3.3, so it is labelled
    '(record layer)', as in Wireshark's 'TLSv1.2 Record Layer'.
    """
    if len(payload) < 5 or payload[0] not in TLS_CONTENT_TYPES or payload[1] != 3 or payload[2] > 4:
        return None
    if int.from_bytes(payload[3:5], "big") > _TLS_MAX_RECORD:
        return None
    record_version = _tls_version_name(int.from_bytes(payload[1:3], "big"))
    info: dict = {"version": f"{record_version} (record layer)", "sni": None}
    messages: list[str] = []
    encrypted = False  # after Change Cipher Spec, handshake records are encrypted
    pos = 0
    while pos + 5 <= len(payload):
        ctype = payload[pos]
        if ctype not in TLS_CONTENT_TYPES or payload[pos + 1] != 3:
            break
        length = int.from_bytes(payload[pos + 3:pos + 5], "big")
        record = payload[pos + 5:pos + 5 + length]
        if ctype == 22 and record and not encrypted and record[0] in TLS_HANDSHAKE_TYPES:
            name = TLS_HANDSHAKE_TYPES[record[0]]
            if record[0] in (1, 2) and len(record) >= 4:
                hello_len = int.from_bytes(record[1:4], "big")
                info.update(_parse_hello(record[4:4 + hello_len], client=record[0] == 1))
        elif ctype == 22:
            name = "Encrypted Handshake Message"
        else:
            name = TLS_CONTENT_TYPES[ctype]
            encrypted = encrypted or ctype == 20
        if not messages or messages[-1] != name:
            messages.append(name)
        pos += 5 + length
    info["message"] = ", ".join(messages)
    return info


def classify_application(pkt: Packet) -> str:
    """Classify the application layer protocol: DNS, HTTP or TLS (by real parsing)."""
    if get_dns_layer(pkt) is not None:
        return "DNS"
    payload = tcp_payload(pkt)
    if payload:
        if parse_tls(payload) is not None:
            return "TLS"
        if parse_http(payload) is not None:
            return "HTTP"
    return OTHER


def display_protocol(network: str, transport: str, application: str) -> str:
    """Pick the single most specific protocol name for the packet table."""
    if application != OTHER:
        return application
    if transport not in (OTHER, NOT_APPLICABLE):
        return transport
    if network != OTHER:
        return network
    return OTHER


# ---------------------------------------------------------------------------
# Distributions (work on the DataFrame produced by packet_parser)
# ---------------------------------------------------------------------------
def _distribution(values: Iterable[str], categories: list[str]) -> pd.DataFrame:
    """Count values into a fixed set of categories, keeping zero counts."""
    counts = Counter(values)
    total = sum(counts.values())
    rows = []
    for cat in categories:
        n = counts.get(cat, 0)
        rows.append(
            {
                "Protocol": cat,
                "Packets": n,
                "Percentage": round(100.0 * n / total, 2) if total else 0.0,
            }
        )
    return pd.DataFrame(rows)


def network_distribution(df: pd.DataFrame) -> pd.DataFrame:
    return _distribution(df["network_protocol"], NETWORK_CATEGORIES)


def transport_distribution(df: pd.DataFrame) -> pd.DataFrame:
    return _distribution(df["transport_protocol"], TRANSPORT_CATEGORIES)


def application_distribution(df: pd.DataFrame) -> pd.DataFrame:
    return _distribution(df["application_protocol"], APPLICATION_CATEGORIES)


def layer_distributions(df: pd.DataFrame) -> Mapping[str, pd.DataFrame]:
    """All three per-layer distributions, keyed by layer name."""
    return {
        "Network Layer": network_distribution(df),
        "Transport Layer": transport_distribution(df),
        "Application Layer": application_distribution(df),
    }
