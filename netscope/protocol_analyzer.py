"""
Protocol classification for NetScope.

Every packet is classified at three separate layers of the TCP/IP model:

    Network layer      -> IPv4, IPv6, ARP, or "Other / Not Detected"
    Transport layer    -> TCP, UDP, ICMP, ICMPv6, "Not Applicable" (ARP),
                          or "Other / Not Detected"
    Application layer  -> DNS, or "Other / Not Detected"

The three classifications are independent. A DNS query is counted once in
each layer's distribution (IPv4 / UDP / DNS), never three times in one chart.

Classification is based on the layers that Scapy actually decoded from the
packet bytes, NOT on port numbers alone. For example, a packet on port 443 is
not assumed to be TLS, and a packet on port 53 is only DNS if Scapy was able to
decode a well-formed DNS header from it.
"""

from __future__ import annotations

from collections import Counter
from typing import Iterable, Mapping

import pandas as pd
from scapy.layers.dns import DNS
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6, _ICMPv6
from scapy.layers.l2 import ARP
from scapy.packet import Packet

# ---------------------------------------------------------------------------
# Category labels (kept in one place so every module uses the same strings)
# ---------------------------------------------------------------------------
OTHER = "Other / Not Detected"
NOT_APPLICABLE = "Not Applicable"

NETWORK_PROTOCOLS = ["IPv4", "IPv6", "ARP"]
TRANSPORT_PROTOCOLS = ["TCP", "UDP", "ICMP", "ICMPv6"]
APPLICATION_PROTOCOLS = ["DNS"]

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


def classify_application(pkt: Packet) -> str:
    """Classify the application layer protocol (only DNS is detected reliably)."""
    return "DNS" if get_dns_layer(pkt) is not None else OTHER


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
