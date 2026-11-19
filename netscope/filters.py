"""
Packet filtering for NetScope.

Filters always return a NEW DataFrame. The original packet DataFrame is never
modified, so dashboard statistics are not affected by what the user filters.
"""

from __future__ import annotations

import pandas as pd

# Filter name -> (column to check, value it must equal)
PROTOCOL_FILTERS = {
    "TCP": ("transport_protocol", "TCP"),
    "UDP": ("transport_protocol", "UDP"),
    "ICMP": ("transport_protocol", "ICMP"),
    "ICMPv6": ("transport_protocol", "ICMPv6"),
    "DNS": ("application_protocol", "DNS"),
    "ARP": ("network_protocol", "ARP"),
    "IPv4": ("network_protocol", "IPv4"),
    "IPv6": ("network_protocol", "IPv6"),
}


def filter_by_protocol(df: pd.DataFrame, protocols: list[str] | None) -> pd.DataFrame:
    """Keep packets that match ANY of the selected protocols.

    Example: ["TCP", "DNS"] keeps all TCP packets plus all DNS packets.
    An empty selection means "no protocol filter".
    """
    if not protocols:
        return df.copy()
    mask = pd.Series(False, index=df.index)
    for name in protocols:
        if name not in PROTOCOL_FILTERS:
            raise ValueError(f"Unknown protocol filter: {name}")
        column, value = PROTOCOL_FILTERS[name]
        mask |= df[column] == value
    return df[mask].copy()


def filter_by_ip(df: pd.DataFrame, column: str, ip_text: str | None) -> pd.DataFrame:
    """Keep packets whose source/destination IP contains the given text.

    Partial matches are allowed, e.g. '192.168.1.' matches the whole subnet.
    """
    if column not in ("src_ip", "dst_ip"):
        raise ValueError("column must be 'src_ip' or 'dst_ip'")
    text = (ip_text or "").strip()
    if not text:
        return df.copy()
    mask = df[column].fillna("").str.contains(text, case=False, regex=False)
    return df[mask].copy()


def apply_filters(
    df: pd.DataFrame,
    protocols: list[str] | None = None,
    src_ip: str | None = None,
    dst_ip: str | None = None,
) -> pd.DataFrame:
    """Apply protocol, source IP and destination IP filters together (AND)."""
    result = filter_by_protocol(df, protocols)
    result = filter_by_ip(result, "src_ip", src_ip)
    result = filter_by_ip(result, "dst_ip", dst_ip)
    return result
