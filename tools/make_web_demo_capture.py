"""
Build a second synthetic demo capture that shows the newer TraceNet features:
HTTP and TLS detection (with SNI), TCP retransmissions and RTT.

Like sample_capture.pcap it contains NO real traffic: every packet is built
with Scapy. The TLS records contain random bytes in place of encrypted data.

Run from the project folder:
    python tools/make_web_demo_capture.py
Output:
    sample_data/web_demo_capture.pcap

The helpers client_hello() and server_hello() are also used by the tests.
"""

from __future__ import annotations

import logging
import os
import random
import struct

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.layers.dns import DNS, DNSQR, DNSRR  # noqa: E402
from scapy.layers.inet import IP, TCP, UDP  # noqa: E402
from scapy.layers.l2 import Ether  # noqa: E402
from scapy.packet import Raw  # noqa: E402
from scapy.utils import wrpcap  # noqa: E402

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTPUT = os.path.join(PROJECT_DIR, "sample_data", "web_demo_capture.pcap")

CLIENT_IP, CLIENT_MAC = "192.168.1.10", "02:00:00:00:00:10"
ROUTER_MAC = "02:00:00:00:00:01"
DNS_SERVER = "8.8.8.8"
HTTP_SERVER = "93.184.216.34"     # example.com
TLS_SERVER = "208.80.154.224"     # wikipedia.org


# ---------------------------------------------------------------------------
# TLS message builders (byte layouts from RFC 8446 and RFC 6066)
# ---------------------------------------------------------------------------
def _record(content_type: int, body: bytes, version: int = 0x0303) -> bytes:
    return struct.pack("!BHH", content_type, version, len(body)) + body


def _handshake(msg_type: int, body: bytes) -> bytes:
    return struct.pack("!B", msg_type) + len(body).to_bytes(3, "big") + body


def _ext(ext_type: int, data: bytes) -> bytes:
    return struct.pack("!HH", ext_type, len(data)) + data


def client_hello(sni: str | None, tls13: bool = True, rnd: random.Random | None = None) -> bytes:
    """A TLS record carrying a Client Hello (optionally with SNI and TLS 1.3)."""
    rnd = rnd or random.Random(1)
    exts = b""
    if sni:
        name = sni.encode()
        entry = b"\x00" + struct.pack("!H", len(name)) + name
        exts += _ext(0, struct.pack("!H", len(entry)) + entry)               # server_name
    if tls13:
        versions = struct.pack("!HHH", 0x3A3A, 0x0304, 0x0303)                # GREASE, 1.3, 1.2
        exts += _ext(43, bytes([len(versions)]) + versions)                  # supported_versions
    suites = struct.pack("!HHH", 0x1301, 0x1302, 0xC02F)
    body = (struct.pack("!H", 0x0303) + bytes(rnd.getrandbits(8) for _ in range(32))
            + b"\x20" + bytes(rnd.getrandbits(8) for _ in range(32))         # session id
            + struct.pack("!H", len(suites)) + suites
            + b"\x01\x00"                                                    # compression: null
            + struct.pack("!H", len(exts)) + exts)
    return _record(22, _handshake(1, body), version=0x0301)


def server_hello(tls13: bool = True, rnd: random.Random | None = None) -> bytes:
    """Server Hello record (+ Change Cipher Spec + encrypted data for TLS 1.3)."""
    rnd = rnd or random.Random(2)
    exts = _ext(43, struct.pack("!H", 0x0304)) if tls13 else b""
    body = (struct.pack("!H", 0x0303) + bytes(rnd.getrandbits(8) for _ in range(32))
            + b"\x00" + struct.pack("!H", 0x1301) + b"\x00"
            + struct.pack("!H", len(exts)) + exts)
    out = _record(22, _handshake(2, body))
    if tls13:
        out += _record(20, b"\x01") + application_data(180, rnd)
    return out


def application_data(size: int, rnd: random.Random | None = None) -> bytes:
    rnd = rnd or random.Random(3)
    return _record(23, bytes(rnd.getrandbits(8) for _ in range(size)))


# ---------------------------------------------------------------------------
# Capture script
# ---------------------------------------------------------------------------
def build_capture() -> list:
    rnd = random.Random(2025)
    packets = []
    clock = [1_731_990_000.0]

    def add(pkt, delay):
        clock[0] += delay
        pkt = Ether(bytes(pkt))
        pkt.time = clock[0]
        packets.append(pkt)

    def out(dst, sport, dport):
        return Ether(src=CLIENT_MAC, dst=ROUTER_MAC) / IP(src=CLIENT_IP, dst=dst) / TCP(sport=sport, dport=dport)

    def back(src, sport, dport):
        return Ether(src=ROUTER_MAC, dst=CLIENT_MAC) / IP(src=src, dst=CLIENT_IP) / TCP(sport=sport, dport=dport)

    class Conn:
        """Tracks the sequence numbers of one TCP connection."""

        def __init__(self, server, sport, dport, rtt):
            self.server, self.sport, self.dport, self.rtt = server, sport, dport, rtt
            self.c = rnd.randrange(2**32)
            self.s = rnd.randrange(2**32)

        def c2s(self, flags, data=b"", delay=0.001, seq=None):
            p = out(self.server, self.sport, self.dport)
            p[TCP].flags, p[TCP].seq, p[TCP].ack = flags, self.c if seq is None else seq, self.s
            add(p / Raw(data) if data else p, delay)

        def s2c(self, flags, data=b"", delay=None, seq=None):
            p = back(self.server, self.dport, self.sport)
            p[TCP].flags, p[TCP].seq, p[TCP].ack = flags, self.s if seq is None else seq, self.c
            add(p / Raw(data) if data else p, self.rtt if delay is None else delay)

        def handshake(self):
            p = out(self.server, self.sport, self.dport)
            p[TCP].flags, p[TCP].seq = "S", self.c
            add(p, 0.05)
            self.c = (self.c + 1) % 2**32
            p = back(self.server, self.dport, self.sport)
            p[TCP].flags, p[TCP].seq, p[TCP].ack = "SA", self.s, self.c
            add(p, self.rtt)
            self.s = (self.s + 1) % 2**32
            self.c2s("A")

    # 1. DNS lookups for both servers
    for name, ip, port in (("example.com", HTTP_SERVER, 53001), ("www.wikipedia.org", TLS_SERVER, 53002)):
        add(Ether(src=CLIENT_MAC, dst=ROUTER_MAC) / IP(src=CLIENT_IP, dst=DNS_SERVER)
            / UDP(sport=port, dport=53) / DNS(id=port, rd=1, qd=DNSQR(qname=name)), 0.2)
        add(Ether(src=ROUTER_MAC, dst=CLIENT_MAC) / IP(src=DNS_SERVER, dst=CLIENT_IP)
            / UDP(sport=53, dport=port) / DNS(id=port, qr=1, ra=1, qd=DNSQR(qname=name),
                                              an=DNSRR(rrname=name, rdata=ip, ttl=300)), 0.018)

    # 2. Plain HTTP: GET, the response is lost once and retransmitted
    http = Conn(HTTP_SERVER, 50100, 80, rtt=0.042)
    http.handshake()
    request = (b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: TraceNet-demo\r\n"
               b"Accept: */*\r\n\r\n")
    http.c2s("PA", request)
    http.c = (http.c + len(request)) % 2**32
    http.s2c("A")
    body = b"<html><body>demo page</body></html>"
    response = (b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: "
                + str(len(body)).encode() + b"\r\n\r\n" + body)
    http.s2c("PA", response, delay=0.004)             # first copy: never acknowledged
    http.s2c("PA", response, delay=0.300)             # retransmission after the timeout
    http.s = (http.s + len(response)) % 2**32
    http.c2s("A", delay=http.rtt / 2)
    http.c2s("FA", delay=0.05)
    http.c = (http.c + 1) % 2**32
    http.s2c("FA")
    http.s = (http.s + 1) % 2**32
    http.c2s("A")

    # 3. HTTPS: TLS 1.3 handshake with SNI, then encrypted data; one client
    #    segment is retransmitted
    tls = Conn(TLS_SERVER, 50200, 443, rtt=0.065)
    tls.handshake()
    hello = client_hello("www.wikipedia.org", rnd=rnd)
    tls.c2s("PA", hello)
    tls.c = (tls.c + len(hello)) % 2**32
    reply = server_hello(rnd=rnd)
    tls.s2c("PA", reply)
    tls.s = (tls.s + len(reply)) % 2**32
    finished = _record(20, b"\x01") + application_data(53, rnd)
    tls.c2s("PA", finished, delay=0.003)
    tls.c = (tls.c + len(finished)) % 2**32
    req = application_data(420, rnd)
    tls.c2s("PA", req, delay=0.002)                   # this copy is lost
    tls.s2c("A", delay=tls.rtt - 0.002)               # server ACKs only the Finished record
    tls.c2s("PA", req, delay=0.250)                   # retransmitted request
    tls.c = (tls.c + len(req)) % 2**32
    tls.s2c("A")
    for size in (1200, 1200, 640):
        data = application_data(size, rnd)
        tls.s2c("PA", data, delay=0.01)
        tls.s = (tls.s + len(data)) % 2**32
    tls.c2s("A", delay=0.002)
    tls.c2s("FA", delay=0.4)
    tls.c = (tls.c + 1) % 2**32
    tls.s2c("FA")
    tls.s = (tls.s + 1) % 2**32
    tls.c2s("A")
    return packets


def main() -> None:
    packets = build_capture()
    os.makedirs(os.path.dirname(OUTPUT), exist_ok=True)
    wrpcap(OUTPUT, packets)
    print(f"Wrote {len(packets)} packets to {OUTPUT}")


if __name__ == "__main__":
    main()
