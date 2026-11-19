"""Tests for the features from the README's Future Scope list:
HTTP/TLS detection, conversations, traffic over time, TCP retransmission and
RTT analysis, and CSV export."""

import io
import random

import pandas as pd
import pytest
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import wrpcap

from netscope import filters
from netscope import protocol_analyzer as pa
from netscope import traffic_statistics as ts
from netscope.packet_parser import COLUMNS, extract_metadata, parse_capture
from tests.conftest import build
from tools.make_web_demo_capture import application_data, build_capture, client_hello, server_hello

HTTP_REQUEST = b"GET /docs/index.html HTTP/1.1\r\nHost: example.com\r\nAccept: */*\r\n\r\n"
HTTP_RESPONSE = b"HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\n\r\nsecret-body"


def tcp_packet(payload: bytes, sport=50000, dport=80):
    eth = Ether(src="aa:aa:aa:aa:aa:01", dst="bb:bb:bb:bb:bb:02")
    return build(eth / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=sport, dport=dport, flags="PA")
                 / Raw(payload))


# ---------------------------------------------------------------------------
# HTTP and TLS detection
# ---------------------------------------------------------------------------
def test_http_request_is_detected():
    r = extract_metadata(tcp_packet(HTTP_REQUEST), 1)
    assert r["application_protocol"] == "HTTP"
    assert r["protocol"] == "HTTP"
    assert r["http_info"] == "GET /docs/index.html"
    assert r["http_host"] == "example.com"
    assert r["tcp_payload_len"] == len(HTTP_REQUEST)


def test_http_response_is_detected_and_body_not_stored():
    r = extract_metadata(tcp_packet(HTTP_RESPONSE, sport=80, dport=50000), 1)
    assert r["application_protocol"] == "HTTP"
    assert r["http_info"] == "404 Not Found"
    assert "secret-body" not in str(r)


def test_http_on_unusual_port_is_detected_by_content():
    r = extract_metadata(tcp_packet(HTTP_REQUEST, dport=8081), 1)
    assert r["application_protocol"] == "HTTP"


@pytest.mark.parametrize("payload", [
    b"GETTING started with networks\r\n",          # starts with GET but is not a request line
    b"GET / HTTP/2.0\r\n\r\n",                     # HTTP/2 is binary, never a text request line
    b"HTTP/1.1 999 Nope\r\n",                      # invalid status code
    b"hello world",
])
def test_text_that_is_not_http(payload):
    assert pa.classify_application(tcp_packet(payload)) == pa.OTHER


def test_tls13_client_hello_with_sni():
    r = extract_metadata(tcp_packet(client_hello("www.example.org"), dport=443), 1)
    assert r["application_protocol"] == "TLS"
    assert r["tls_message"] == "Client Hello"
    assert r["tls_version"] == "TLS 1.3"           # from supported_versions, GREASE ignored
    assert r["tls_sni"] == "www.example.org"


def test_tls12_client_hello_without_extensions_for_version():
    info = pa.parse_tls(client_hello("a.test", tls13=False))
    assert info["version"] == "TLS 1.2"
    assert info["sni"] == "a.test"


def test_client_hello_without_sni():
    info = pa.parse_tls(client_hello(None))
    assert info["message"] == "Client Hello"
    assert info["sni"] is None


def test_server_hello_lists_all_records():
    info = pa.parse_tls(server_hello())
    assert info["message"] == "Server Hello, Change Cipher Spec, Application Data"
    assert info["version"] == "TLS 1.3"


def test_application_data_version_is_record_layer():
    info = pa.parse_tls(application_data(50))
    assert info["message"] == "Application Data"
    assert info["version"] == "TLS 1.2 (record layer)"


def test_random_bytes_on_port_443_are_not_tls():
    rnd = random.Random(7)
    for _ in range(200):
        payload = bytes(rnd.getrandbits(8) for _ in range(60))
        if payload[0] in pa.TLS_CONTENT_TYPES and payload[1] == 3:
            continue  # skip the rare random payload that really looks like a record header
        assert pa.classify_application(tcp_packet(payload, dport=443)) == pa.OTHER


def test_truncated_client_hello_does_not_crash():
    hello = client_hello("www.example.org")
    for cut in range(6, len(hello)):  # from the first byte of the handshake message on
        info = pa.parse_tls(hello[:cut])
        assert info is not None and info["message"] == "Client Hello"


def test_ethernet_padding_is_not_counted_as_payload():
    # A 1-byte payload makes a frame shorter than 60 bytes, so padding is added.
    pkt = Ether(bytes(tcp_packet(b"x")) + b"\x00" * 6)
    assert len(pa.tcp_payload(pkt)) == 1


def test_new_protocol_filters(tmp_path):
    path = tmp_path / "web.pcap"
    wrpcap(str(path), [tcp_packet(HTTP_REQUEST), tcp_packet(client_hello("x.test"), dport=443)])
    df, _ = parse_capture(str(path))
    assert list(filters.apply_filters(df, ["HTTP"])["packet_no"]) == [1]
    assert list(filters.apply_filters(df, ["TLS"])["packet_no"]) == [2]
    assert len(filters.apply_filters(df, ["HTTP", "TLS"])) == 2


# ---------------------------------------------------------------------------
# CSV export
# ---------------------------------------------------------------------------
def test_csv_export_contains_filtered_metadata_only(pcap_file):
    df, _ = parse_capture(pcap_file)
    view = filters.apply_filters(df, ["ICMP"])
    data = filters.to_csv(view)
    back = pd.read_csv(io.BytesIO(data))
    assert list(back.columns) == COLUMNS
    assert list(back["packet_no"]) == list(view["packet_no"])
    assert b"xxxxxxxxxx" not in filters.to_csv(df)  # the UDP payload bytes are not exported


# ---------------------------------------------------------------------------
# Conversations and traffic over time
# ---------------------------------------------------------------------------
def _df(rows, columns):
    df = pd.DataFrame(rows, columns=columns)
    return df


def test_conversations_combine_both_directions():
    df = _df([
        (1, 0.0, "10.0.0.1", "10.0.0.2", "IPv4", "TCP", 100),
        (2, 0.5, "10.0.0.2", "10.0.0.1", "IPv4", "TCP", 60),
        (3, 1.0, "10.0.0.1", "10.0.0.2", "IPv4", "DNS", 80),
        (4, 1.2, "10.0.0.1", "10.0.0.3", "IPv4", "UDP", 50),
        (5, 1.5, "10.0.0.1", "10.0.0.254", "ARP", "ARP", 42),   # not an IP conversation
    ], ["packet_no", "timestamp", "src_ip", "dst_ip", "network_protocol", "protocol", "length"])
    conv = ts.conversations(df)
    assert len(conv) == 2
    top = conv.iloc[0]
    assert (top["Address A"], top["Address B"]) == ("10.0.0.1", "10.0.0.2")
    assert (top["Packets"], top["Bytes"]) == (3, 240)
    assert (top["Packets A→B"], top["Bytes A→B"], top["Packets B→A"], top["Bytes B→A"]) == (2, 180, 1, 60)
    assert top["Duration (s)"] == 1.0
    assert top["Protocols"] == "DNS, TCP"


def test_traffic_over_time_keeps_empty_intervals():
    df = _df([(1, 0.0, 100), (2, 0.4, 50), (3, 2.1, 70)], ["packet_no", "relative_time", "length"])
    tot = ts.traffic_over_time(df, interval=1)
    assert list(tot["Time (s)"]) == [0, 1, 2]
    assert list(tot["Packets"]) == [2, 0, 1]
    assert list(tot["Bytes"]) == [150, 0, 70]


def test_choose_interval():
    assert ts.choose_interval(10.5) == 0.5
    assert ts.choose_interval(3600) == 120


# ---------------------------------------------------------------------------
# TCP retransmission and RTT
# ---------------------------------------------------------------------------
TCP_COLS = ["packet_no", "timestamp", "src_ip", "src_port", "dst_ip", "dst_port",
            "tcp_flags", "tcp_seq", "tcp_ack", "tcp_payload_len"]
C, S = ("10.0.0.1", 5000), ("10.0.0.2", 80)


def _tcp_df(rows):
    df = pd.DataFrame([(n, t, *a, *b, f, seq, ack, ln) for n, t, a, b, f, seq, ack, ln in rows],
                      columns=TCP_COLS)
    df["transport_protocol"] = "TCP"
    return df


def test_retransmission_and_rtt():
    seq_max = 2**32 - 10   # the client's sequence numbers wrap around during the test
    df = _tcp_df([
        (1, 0.000, C, S, "SYN", seq_max, 0, 0),
        (2, 0.050, S, C, "SYN, ACK", 700, seq_max + 1, 0),
        (3, 0.051, C, S, "ACK", seq_max + 1, 701, 0),
        (4, 0.060, C, S, "PSH, ACK", seq_max + 1, 701, 20),    # lost
        (5, 0.360, C, S, "PSH, ACK", seq_max + 1, 701, 20),    # retransmission
        (6, 0.410, S, C, "ACK", 701, (seq_max + 21) % 2**32, 0),
        (7, 0.420, C, S, "PSH, ACK", (seq_max + 21) % 2**32, 701, 5),
        (8, 0.460, S, C, "ACK", 701, (seq_max + 26) % 2**32, 0),
        (9, 0.470, S, C, "ACK", 701, (seq_max + 26) % 2**32, 0),   # duplicate ACK: no data, not a retransmission
    ])
    retx = ts.tcp_retransmissions(df)
    assert list(retx["Packet"]) == [5]
    assert retx.iloc[0]["Original packet"] == 4
    assert retx.iloc[0]["Delay (ms)"] == 300.0

    rtt = ts.tcp_rtt(df).set_index("Sender")
    client = rtt.loc["10.0.0.1:5000"]
    # Samples: SYN -> SYN-ACK (50 ms) and packet 7 -> 8 (40 ms). Packets 4/5 are
    # skipped because the segment was sent twice (Karn's algorithm).
    assert client["RTT samples"] == 2
    assert client["Retransmissions"] == 1
    assert client["Min RTT (ms)"] == 40.0
    assert client["Max RTT (ms)"] == 50.0
    server = rtt.loc["10.0.0.2:80"]
    assert server["RTT samples"] == 1 and server["Min RTT (ms)"] == 1.0   # SYN-ACK -> ACK


def test_handshake_rtt_column():
    df = _tcp_df([
        (1, 10.000, C, S, "SYN", 100, 0, 0),
        (2, 10.025, S, C, "SYN, ACK", 300, 101, 0),
        (3, 10.026, C, S, "ACK", 101, 301, 0),
    ])
    hs = ts.find_tcp_handshakes(df)
    assert hs.iloc[0]["Handshake RTT (ms)"] == 25.0


# ---------------------------------------------------------------------------
# End to end: the web demo capture
# ---------------------------------------------------------------------------
def test_web_demo_capture_end_to_end(tmp_path):
    path = tmp_path / "web_demo.pcap"
    wrpcap(str(path), build_capture())
    df, info = parse_capture(str(path))
    assert info["warning"] is None and info["malformed_count"] == 0

    app = pa.application_distribution(df).set_index("Protocol")["Packets"]
    assert app["DNS"] == 4 and app["HTTP"] == 3 and app["TLS"] == 8

    http = ts.http_requests(df)
    assert list(http[["Host", "Request", "Response"]].iloc[0]) == ["example.com", "GET /index.html", "200 OK"]
    assert list(ts.tls_server_names(df)["Server name (SNI)"]) == ["www.wikipedia.org"]
    assert len(ts.find_tcp_handshakes(df)) == 2
    assert len(ts.tcp_retransmissions(df)) == 2

    rtt = ts.tcp_rtt(df).set_index("Sender")
    assert rtt.loc["192.168.1.10:50100", "Avg RTT (ms)"] == pytest.approx(42, abs=0.01)
    assert rtt.loc["192.168.1.10:50200", "Max RTT (ms)"] == pytest.approx(65, abs=0.01)

    conv = ts.conversations(df)
    assert conv["Packets"].sum() == len(df)
    assert ts.traffic_over_time(df)["Packets"].sum() == len(df)
