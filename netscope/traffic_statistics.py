"""
Traffic statistics for NetScope.

All functions take the packet DataFrame from packet_parser and return values
computed from the real packets in it. Nothing here is hardcoded.
"""

from __future__ import annotations

from typing import Any

import pandas as pd


def total_packets(df: pd.DataFrame) -> int:
    return int(len(df))


def total_bytes(df: pd.DataFrame) -> int:
    """Sum of captured packet lengths, in bytes."""
    return int(df["length"].sum()) if len(df) else 0


def format_bytes(num_bytes: int) -> str:
    """Human readable size, e.g. 1536 -> '1.50 KB'."""
    size = float(num_bytes)
    for unit in ["bytes", "KB", "MB", "GB"]:
        if size < 1024 or unit == "GB":
            return f"{int(size)} bytes" if unit == "bytes" else f"{size:.2f} {unit}"
        size /= 1024
    return f"{size:.2f} GB"


def unique_source_ips(df: pd.DataFrame) -> int:
    return int(df["src_ip"].dropna().nunique())


def unique_destination_ips(df: pd.DataFrame) -> int:
    return int(df["dst_ip"].dropna().nunique())


def dns_packet_count(df: pd.DataFrame) -> int:
    return int((df["application_protocol"] == "DNS").sum())


def top_ips(df: pd.DataFrame, column: str, n: int = 5) -> pd.DataFrame:
    """Top-n IP addresses in 'src_ip' or 'dst_ip' by packet count."""
    counts = df[column].dropna().value_counts().head(n)
    return pd.DataFrame({"IP Address": counts.index, "Packets": counts.values})


def capture_duration(df: pd.DataFrame) -> float:
    """Seconds between the first and the last packet."""
    ts = df["timestamp"].dropna()
    return float(ts.max() - ts.min()) if len(ts) else 0.0


def summary(df: pd.DataFrame) -> dict[str, Any]:
    """All overview statistics in one dictionary."""
    return {
        "total_packets": total_packets(df),
        "total_bytes": total_bytes(df),
        "unique_src_ips": unique_source_ips(df),
        "unique_dst_ips": unique_destination_ips(df),
        "dns_packets": dns_packet_count(df),
        "duration": capture_duration(df),
    }


# ---------------------------------------------------------------------------
# TCP analysis
# ---------------------------------------------------------------------------
def tcp_flag_counts(df: pd.DataFrame) -> pd.DataFrame:
    """Count TCP packets by flag combination (e.g. 'SYN', 'SYN, ACK')."""
    tcp = df[df["transport_protocol"] == "TCP"]
    counts = tcp["tcp_flags"].fillna("(none)").replace("", "(none)").value_counts()
    return pd.DataFrame({"TCP Flags": counts.index, "Packets": counts.values})


def find_tcp_handshakes(df: pd.DataFrame) -> pd.DataFrame:
    """Detect completed TCP three-way handshakes.

    A handshake between client C and server S is:
        1. C -> S  SYN        seq = x
        2. S -> C  SYN, ACK   seq = y, ack = x + 1
        3. C -> S  ACK        ack = y + 1   (no SYN flag)
    We match the three packets using IP addresses, ports and the
    sequence / acknowledgement numbers.
    """
    tcp = df[df["transport_protocol"] == "TCP"].sort_values("packet_no")
    pending_syn: dict[tuple, dict] = {}     # key: (cip, cport, sip, sport)
    pending_synack: dict[tuple, dict] = {}
    handshakes = []
    mod = 2**32  # TCP sequence numbers wrap around at 2^32

    for row in tcp.itertuples(index=False):
        flags = set((row.tcp_flags or "").split(", "))
        key = (row.src_ip, row.src_port, row.dst_ip, row.dst_port)
        reverse = (row.dst_ip, row.dst_port, row.src_ip, row.src_port)

        if flags >= {"SYN"} and "ACK" not in flags:
            pending_syn[key] = {"syn_no": row.packet_no, "seq": row.tcp_seq}
        elif flags >= {"SYN", "ACK"}:
            syn = pending_syn.get(reverse)
            if syn and row.tcp_ack == (syn["seq"] + 1) % mod:
                pending_synack[reverse] = {**syn, "synack_no": row.packet_no, "seq2": row.tcp_seq}
        elif "ACK" in flags and "SYN" not in flags:
            sa = pending_synack.get(key)
            if sa and row.tcp_ack == (sa["seq2"] + 1) % mod:
                handshakes.append(
                    {
                        "Client": f"{row.src_ip}:{row.src_port}",
                        "Server": f"{row.dst_ip}:{row.dst_port}",
                        "SYN (packet)": sa["syn_no"],
                        "SYN-ACK (packet)": sa["synack_no"],
                        "ACK (packet)": row.packet_no,
                    }
                )
                del pending_synack[key]
                pending_syn.pop(key, None)

    return pd.DataFrame(
        handshakes,
        columns=["Client", "Server", "SYN (packet)", "SYN-ACK (packet)", "ACK (packet)"],
    )


# ---------------------------------------------------------------------------
# ICMP and DNS analysis
# ---------------------------------------------------------------------------
def icmp_type_counts(df: pd.DataFrame) -> pd.DataFrame:
    icmp = df[df["transport_protocol"].isin(["ICMP", "ICMPv6"])]
    if icmp.empty:
        return pd.DataFrame(columns=["Protocol", "Message Type", "Packets"])
    counts = icmp.groupby(["transport_protocol", "icmp_info"]).size().reset_index(name="Packets")
    counts.columns = ["Protocol", "Message Type", "Packets"]
    return counts.sort_values("Packets", ascending=False, ignore_index=True)


def top_dns_queries(df: pd.DataFrame, n: int = 10) -> pd.DataFrame:
    """Most frequently queried domain names (DNS queries only, not responses)."""
    q = df[(df["application_protocol"] == "DNS") & (df["dns_direction"] == "Query")]
    counts = q["dns_query"].dropna().value_counts().head(n)
    return pd.DataFrame({"Domain": counts.index, "Queries": counts.values})
