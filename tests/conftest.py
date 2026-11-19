"""Shared synthetic packet fixtures (used ONLY by automated tests)."""

import logging
import os
import sys

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402
from scapy.layers.dns import DNS, DNSQR  # noqa: E402
from scapy.layers.inet import ICMP, IP, TCP, UDP  # noqa: E402
from scapy.layers.inet6 import ICMPv6EchoRequest, IPv6  # noqa: E402
from scapy.layers.l2 import ARP, Ether  # noqa: E402
from scapy.packet import Raw  # noqa: E402
from scapy.utils import wrpcap, wrpcapng  # noqa: E402

MAC_A = "aa:aa:aa:aa:aa:01"
MAC_B = "bb:bb:bb:bb:bb:02"


def build(pkt, t=1_700_000_000.0):
    """Turn a constructed packet into a 'captured' one (as if read from a file)."""
    built = Ether(bytes(pkt))
    built.time = t
    return built


@pytest.fixture
def sample_packets():
    eth = Ether(src=MAC_A, dst=MAC_B)
    return {
        "tcp": build(eth / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=50000, dport=443, flags="S", seq=100)),
        "udp": build(eth / IP(src="10.0.0.1", dst="10.0.0.3") / UDP(sport=40000, dport=9999) / Raw(b"x" * 10)),
        "echo_request": build(eth / IP(src="10.0.0.1", dst="8.8.8.8") / ICMP(type=8)),
        "echo_reply": build(eth / IP(src="8.8.8.8", dst="10.0.0.1") / ICMP(type=0)),
        "arp": build(Ether(src=MAC_A, dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, psrc="10.0.0.1", pdst="10.0.0.254")),
        "dns": build(eth / IP(src="10.0.0.1", dst="8.8.8.8") / UDP(sport=53000, dport=53)
                     / DNS(rd=1, qd=DNSQR(qname="example.com", qtype="A"))),
        "ipv6_tcp": build(eth / IPv6(src="fe80::1", dst="fe80::2") / TCP(sport=1234, dport=80)),
        "icmpv6": build(eth / IPv6(src="fe80::1", dst="fe80::2") / ICMPv6EchoRequest()),
        # IPv4 carrying protocol 47 (GRE) payload that we do not decode.
        "unsupported": build(eth / IP(src="10.0.0.1", dst="10.0.0.9", proto=47) / Raw(b"\x00" * 8)),
        # Ethernet frame with an unknown EtherType and no network layer.
        "no_network": build(Ether(src=MAC_A, dst=MAC_B, type=0x88B5) / Raw(b"\x01\x02\x03")),
        # Port 53 traffic that is NOT valid DNS (random bytes).
        "fake_dns": build(eth / IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=1111, dport=53) / Raw(b"\xff" * 5)),
    }


@pytest.fixture
def pcap_file(tmp_path, sample_packets):
    path = tmp_path / "sample.pcap"
    wrpcap(str(path), list(sample_packets.values()))
    return str(path)


@pytest.fixture
def pcapng_file(tmp_path, sample_packets):
    path = tmp_path / "sample.pcapng"
    wrpcapng(str(path), list(sample_packets.values()))
    return str(path)
