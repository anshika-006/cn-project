"""Tests for packet parsing and capture file handling."""

import pytest
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from netscope.packet_parser import (
    CaptureFileError,
    detect_format,
    extract_metadata,
    format_tcp_flags,
    parse_capture,
)

from conftest import MAC_A, MAC_B, build


def test_ipv4_tcp_packet(sample_packets):
    r = extract_metadata(sample_packets["tcp"], 1)
    assert r["src_ip"] == "10.0.0.1" and r["dst_ip"] == "10.0.0.2"
    assert r["src_port"] == 50000 and r["dst_port"] == 443
    assert r["src_mac"] == MAC_A and r["dst_mac"] == MAC_B
    assert r["tcp_flags"] == "SYN" and r["tcp_seq"] == 100
    assert r["protocol"] == "TCP"
    assert r["length"] == len(bytes(sample_packets["tcp"]))
    assert r["parse_error"] is None


def test_ipv4_udp_packet(sample_packets):
    r = extract_metadata(sample_packets["udp"], 2)
    assert (r["network_protocol"], r["transport_protocol"]) == ("IPv4", "UDP")
    assert r["src_port"] == 40000 and r["dst_port"] == 9999
    assert r["tcp_flags"] is None


def test_icmp_echo_request(sample_packets):
    r = extract_metadata(sample_packets["echo_request"], 1)
    assert r["protocol"] == "ICMP"
    assert r["icmp_type"] == 8 and r["icmp_info"] == "echo-request"
    assert r["src_port"] is None and r["dst_port"] is None


def test_icmp_echo_reply(sample_packets):
    r = extract_metadata(sample_packets["echo_reply"], 1)
    assert r["icmp_type"] == 0 and r["icmp_info"] == "echo-reply"
    assert r["src_ip"] == "8.8.8.8"


def test_arp_packet(sample_packets):
    r = extract_metadata(sample_packets["arp"], 1)
    assert r["network_protocol"] == "ARP"
    assert r["transport_protocol"] == "Not Applicable"
    assert r["src_ip"] == "10.0.0.1" and r["dst_ip"] == "10.0.0.254"
    assert r["arp_operation"].startswith("Request")
    assert r["src_port"] is None


def test_dns_query_packet(sample_packets):
    r = extract_metadata(sample_packets["dns"], 1)
    assert r["application_protocol"] == "DNS"
    assert r["dns_query"] == "example.com"
    assert r["dns_query_type"] == "A"
    assert r["dns_direction"] == "Query"


def test_port_53_without_dns_is_not_dns(sample_packets):
    r = extract_metadata(sample_packets["fake_dns"], 1)
    assert r["application_protocol"] == "Other / Not Detected"
    assert r["dns_query"] is None


def test_ipv6_packets(sample_packets):
    r = extract_metadata(sample_packets["ipv6_tcp"], 1)
    assert r["network_protocol"] == "IPv6"
    assert r["src_ip"] == "fe80::1" and r["dst_port"] == 80
    r6 = extract_metadata(sample_packets["icmpv6"], 2)
    assert r6["transport_protocol"] == "ICMPv6"
    assert r6["icmp_info"] == "Echo Request"


def test_missing_or_unsupported_layers(sample_packets):
    r = extract_metadata(sample_packets["unsupported"], 1)
    assert r["network_protocol"] == "IPv4"
    assert r["transport_protocol"] == "Other / Not Detected"
    assert r["src_port"] is None

    r = extract_metadata(sample_packets["no_network"], 2)
    assert r["network_protocol"] == "Other / Not Detected"
    assert r["src_ip"] is None and r["dst_ip"] is None
    assert r["src_mac"] == MAC_A  # Ethernet header is still read
    assert r["protocol"] == "Other / Not Detected"


def test_truncated_tcp_header_does_not_crash():
    # IP header says TCP, but only 4 bytes of TCP header are present.
    raw = bytes(Ether(src=MAC_A, dst=MAC_B) / IP(src="1.1.1.1", dst="2.2.2.2") / TCP())[:38]
    pkt = Ether(raw)
    pkt.time = 1.0
    r = extract_metadata(pkt, 1)
    assert r["packet_no"] == 1
    assert r["network_protocol"] == "IPv4"


def test_payload_is_not_stored(sample_packets):
    r = extract_metadata(sample_packets["udp"], 1)
    assert not any(isinstance(v, bytes) for v in r.values())
    assert "xxxxxxxxxx" not in str(r)


def test_format_tcp_flags():
    assert format_tcp_flags("SA") == "SYN, ACK"
    assert format_tcp_flags("FA") == "FIN, ACK"
    assert format_tcp_flags("") == ""


@pytest.mark.parametrize("fixture_name, fmt", [("pcap_file", "pcap"), ("pcapng_file", "pcapng")])
def test_parse_pcap_and_pcapng(request, sample_packets, fixture_name, fmt):
    path = request.getfixturevalue(fixture_name)
    assert detect_format(path) == fmt
    df, info = parse_capture(path)
    assert info["format"] == fmt
    # Every packet appears exactly once, numbered 1..N.
    assert len(df) == len(sample_packets) == info["packet_count"]
    assert list(df["packet_no"]) == list(range(1, len(sample_packets) + 1))
    assert df["timestamp"].notna().all()
    assert info["warning"] is None


def test_empty_capture_file(tmp_path):
    path = tmp_path / "empty.pcap"
    path.write_bytes(b"")
    with pytest.raises(CaptureFileError, match="empty"):
        parse_capture(str(path))


def test_capture_with_header_but_no_packets(tmp_path):
    from scapy.utils import wrpcap
    path = tmp_path / "nopackets.pcap"
    wrpcap(str(path), [])
    with pytest.raises(CaptureFileError):
        parse_capture(str(path))


def test_invalid_file(tmp_path):
    path = tmp_path / "notes.pcap"
    path.write_text("this is not a capture file")
    with pytest.raises(CaptureFileError, match="not a valid"):
        parse_capture(str(path))


def test_corrupted_header(tmp_path):
    path = tmp_path / "broken.pcap"
    path.write_bytes(b"\xd4\xc3\xb2\xa1\x02\x00")  # valid magic, header cut off
    with pytest.raises(CaptureFileError):
        parse_capture(str(path))


@pytest.mark.parametrize("fixture_name", ["pcap_file", "pcapng_file"])
def test_truncated_capture_is_reported(request, tmp_path, sample_packets, fixture_name):
    data = open(request.getfixturevalue(fixture_name), "rb").read()
    path = tmp_path / "truncated.cap"
    path.write_bytes(data[:-10])  # cut the last packet short
    df, info = parse_capture(str(path))
    assert len(sample_packets) - 1 <= len(df) <= len(sample_packets)
    assert info["warning"] is not None
    assert "cut off" in info["warning"]


def test_complete_capture_is_not_reported_as_truncated(pcap_file, pcapng_file):
    from netscope.packet_parser import is_truncated
    assert not is_truncated(pcap_file, "pcap")
    assert not is_truncated(pcapng_file, "pcapng")
