"""Tests for protocol classification and distributions."""

import pandas as pd
import pytest

from netscope import filters
from netscope import protocol_analyzer as pa
from netscope import traffic_statistics as ts
from netscope.packet_parser import parse_capture


@pytest.mark.parametrize(
    "name, network, transport, application",
    [
        ("tcp", "IPv4", "TCP", pa.OTHER),
        ("udp", "IPv4", "UDP", pa.OTHER),
        ("echo_request", "IPv4", "ICMP", pa.OTHER),
        ("echo_reply", "IPv4", "ICMP", pa.OTHER),
        ("arp", "ARP", pa.NOT_APPLICABLE, pa.OTHER),
        ("dns", "IPv4", "UDP", "DNS"),
        ("ipv6_tcp", "IPv6", "TCP", pa.OTHER),
        ("icmpv6", "IPv6", "ICMPv6", pa.OTHER),
        ("unsupported", "IPv4", pa.OTHER, pa.OTHER),
        ("no_network", pa.OTHER, pa.OTHER, pa.OTHER),
        ("fake_dns", "IPv4", "UDP", pa.OTHER),
    ],
)
def test_layer_classification(sample_packets, name, network, transport, application):
    pkt = sample_packets[name]
    assert pa.classify_network(pkt) == network
    assert pa.classify_transport(pkt) == transport
    assert pa.classify_application(pkt) == application


def test_port_443_is_not_assumed_tls(sample_packets):
    # TCP to port 443 must not be labelled TLS/HTTPS without real parsing.
    assert pa.classify_application(sample_packets["tcp"]) == pa.OTHER


def test_display_protocol_picks_most_specific():
    assert pa.display_protocol("IPv4", "UDP", "DNS") == "DNS"
    assert pa.display_protocol("IPv4", "TCP", pa.OTHER) == "TCP"
    assert pa.display_protocol("ARP", pa.NOT_APPLICABLE, pa.OTHER) == "ARP"
    assert pa.display_protocol(pa.OTHER, pa.OTHER, pa.OTHER) == pa.OTHER


def test_distributions_count_each_packet_once_per_layer(pcap_file):
    df, _ = parse_capture(pcap_file)
    for dist in pa.layer_distributions(df).values():
        assert dist["Packets"].sum() == len(df)
        assert dist["Percentage"].sum() == pytest.approx(100, abs=0.1)

    net = pa.network_distribution(df).set_index("Protocol")["Packets"]
    assert net["IPv4"] == 7 and net["IPv6"] == 2 and net["ARP"] == 1 and net[pa.OTHER] == 1

    trans = pa.transport_distribution(df).set_index("Protocol")["Packets"]
    assert trans["TCP"] == 2 and trans["UDP"] == 3 and trans["ICMP"] == 2
    assert trans["ICMPv6"] == 1 and trans[pa.NOT_APPLICABLE] == 1 and trans[pa.OTHER] == 2

    app = pa.application_distribution(df).set_index("Protocol")["Packets"]
    assert app["DNS"] == 1 and app[pa.OTHER] == 10


def test_zero_count_categories_are_kept():
    df = pd.DataFrame({"network_protocol": ["IPv4"], "transport_protocol": ["TCP"],
                       "application_protocol": [pa.OTHER]})
    trans = pa.transport_distribution(df).set_index("Protocol")["Packets"]
    assert trans["ICMPv6"] == 0  # zero packets, not "unknown"


def test_statistics(pcap_file):
    df, _ = parse_capture(pcap_file)
    s = ts.summary(df)
    assert s["total_packets"] == 11
    assert s["total_bytes"] == int(df["length"].sum()) > 0
    assert s["dns_packets"] == 1
    # src IPs: 10.0.0.1, 8.8.8.8, fe80::1 (ARP sender 10.0.0.1 counted once)
    assert s["unique_src_ips"] == 3
    top = ts.top_ips(df, "src_ip")
    assert top.iloc[0]["IP Address"] == "10.0.0.1"


def test_filters_do_not_modify_original(pcap_file):
    df, _ = parse_capture(pcap_file)
    before = df.copy()
    assert len(filters.apply_filters(df, ["TCP"])) == 2
    assert len(filters.apply_filters(df, ["UDP"])) == 3
    assert len(filters.apply_filters(df, ["ICMP"])) == 2
    assert len(filters.apply_filters(df, ["ICMPv6"])) == 1
    assert len(filters.apply_filters(df, ["DNS"])) == 1
    assert len(filters.apply_filters(df, ["TCP", "DNS"])) == 3
    assert len(filters.apply_filters(df, src_ip="8.8.8.8")) == 1
    assert len(filters.apply_filters(df, dst_ip="8.8.8.8")) == 2
    assert len(filters.apply_filters(df, ["ICMP"], src_ip="10.0.0.1", dst_ip="8.8.8.8")) == 1
    assert len(filters.apply_filters(df)) == len(df)
    pd.testing.assert_frame_equal(df, before)


def test_tcp_handshake_detection():
    rows = [
        # packet_no, src, sport, dst, dport, flags, seq, ack
        (1, "10.0.0.1", 5000, "10.0.0.2", 80, "SYN", 100, 0),
        (2, "10.0.0.2", 80, "10.0.0.1", 5000, "SYN, ACK", 300, 101),
        (3, "10.0.0.1", 5000, "10.0.0.2", 80, "ACK", 101, 301),
        (4, "10.0.0.1", 5001, "10.0.0.2", 80, "SYN", 500, 0),  # never answered
    ]
    df = pd.DataFrame(rows, columns=["packet_no", "src_ip", "src_port", "dst_ip", "dst_port",
                                     "tcp_flags", "tcp_seq", "tcp_ack"])
    df["transport_protocol"] = "TCP"
    hs = ts.find_tcp_handshakes(df)
    assert len(hs) == 1
    assert hs.iloc[0]["Client"] == "10.0.0.1:5000"
    assert list(hs.iloc[0][["SYN (packet)", "SYN-ACK (packet)", "ACK (packet)"]]) == [1, 2, 3]
