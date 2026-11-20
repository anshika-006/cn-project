"""
Build the synthetic demo capture used by the "Use sample capture" option.

The file contains NO real network traffic: every packet is constructed with
Scapy, so it is safe to share and to show in a demo. It covers every protocol
TraceNet understands (Ethernet, ARP, IPv4, IPv6, TCP, UDP, ICMP, ICMPv6, DNS).

Run from the project folder:
    python tools/make_sample_capture.py
Output:
    sample_data/sample_capture.pcap
"""

from __future__ import annotations

import logging
import os
import random

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.layers.dns import DNS, DNSQR, DNSRR  # noqa: E402
from scapy.layers.inet import ICMP, IP, TCP, UDP  # noqa: E402
from scapy.layers.inet6 import ICMPv6EchoReply, ICMPv6EchoRequest, IPv6  # noqa: E402
from scapy.layers.l2 import ARP, Ether  # noqa: E402
from scapy.packet import Raw  # noqa: E402
from scapy.utils import wrpcap  # noqa: E402

PROJECT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTPUT = os.path.join(PROJECT_DIR, "sample_data", "sample_capture.pcap")

# Private lab addresses for the "local" side of the network.
LAPTOP_IP, LAPTOP_MAC = "192.168.1.10", "02:00:00:00:00:10"
PHONE_IP, PHONE_MAC = "192.168.1.23", "02:00:00:00:00:23"
ROUTER_IP, ROUTER_MAC = "192.168.1.1", "02:00:00:00:00:01"
LAPTOP_IP6, ROUTER_IP6 = "fe80::10", "fe80::1"
DNS_SERVER = "8.8.8.8"

# Well-known public sites the "laptop" visits (domain -> IP returned by DNS).
SITES = {
    "example.com": "93.184.216.34",
    "wikipedia.org": "208.80.154.224",
    "github.com": "140.82.112.3",
    "python.org": "151.101.0.223",
}

random.seed(2024)  # same file every time the script runs
packets = []
clock = 1_731_900_000.0


def add(pkt, gap=(0.002, 0.08)):
    """Append a packet with a slightly increasing timestamp."""
    global clock
    clock += random.uniform(*gap)
    pkt = Ether(bytes(pkt))  # rebuild so lengths and checksums are filled in
    pkt.time = clock
    packets.append(pkt)


def eth(src_mac, dst_mac):
    return Ether(src=src_mac, dst=dst_mac)


def out(mac=LAPTOP_MAC):
    return eth(mac, ROUTER_MAC)


def back(mac=LAPTOP_MAC):
    return eth(ROUTER_MAC, mac)


# 1. ARP: the laptop looks up the router's MAC address.
add(eth(LAPTOP_MAC, "ff:ff:ff:ff:ff:ff") / ARP(op=1, hwsrc=LAPTOP_MAC, psrc=LAPTOP_IP, pdst=ROUTER_IP))
add(eth(ROUTER_MAC, LAPTOP_MAC) / ARP(op=2, hwsrc=ROUTER_MAC, psrc=ROUTER_IP, hwdst=LAPTOP_MAC, pdst=LAPTOP_IP))

# 2. ICMP: "ping 8.8.8.8" (4 echo requests and replies).
for seq in range(1, 5):
    add(out() / IP(src=LAPTOP_IP, dst=DNS_SERVER) / ICMP(type=8, id=1, seq=seq) / Raw(b"abcdefghijklmnop"), (0.9, 1.0))
    add(back() / IP(src=DNS_SERVER, dst=LAPTOP_IP) / ICMP(type=0, id=1, seq=seq) / Raw(b"abcdefghijklmnop"), (0.01, 0.03))

# 3. For each website: DNS lookup, TCP three-way handshake, data, close.
for i, (domain, site_ip) in enumerate(SITES.items()):
    dns_port = random.randint(49152, 65535)
    add(out() / IP(src=LAPTOP_IP, dst=DNS_SERVER) / UDP(sport=dns_port, dport=53)
        / DNS(id=100 + i, rd=1, qd=DNSQR(qname=domain, qtype="A")), (0.3, 0.6))
    add(back() / IP(src=DNS_SERVER, dst=LAPTOP_IP) / UDP(sport=53, dport=dns_port)
        / DNS(id=100 + i, qr=1, rd=1, ra=1, qd=DNSQR(qname=domain, qtype="A"),
              an=DNSRR(rrname=domain, type="A", ttl=300, rdata=site_ip)))

    port = random.randint(49152, 65535)
    c_seq, s_seq = random.randint(1000, 9_000_000), random.randint(1000, 9_000_000)
    tcp = lambda **kw: TCP(sport=port, dport=443, window=64240, **kw)  # noqa: E731
    rtcp = lambda **kw: TCP(sport=443, dport=port, window=65535, **kw)  # noqa: E731
    up = IP(src=LAPTOP_IP, dst=site_ip)
    down = IP(src=site_ip, dst=LAPTOP_IP)

    add(out() / up / tcp(flags="S", seq=c_seq))
    add(back() / down / rtcp(flags="SA", seq=s_seq, ack=c_seq + 1))
    add(out() / up / tcp(flags="A", seq=c_seq + 1, ack=s_seq + 1))
    # Encrypted-looking payload (random bytes; TraceNet never displays payloads).
    hello, reply = random.randbytes(220), random.randbytes(1200)
    add(out() / up / tcp(flags="PA", seq=c_seq + 1, ack=s_seq + 1) / Raw(hello))
    add(back() / down / rtcp(flags="A", seq=s_seq + 1, ack=c_seq + 1 + len(hello)))
    add(back() / down / rtcp(flags="PA", seq=s_seq + 1, ack=c_seq + 1 + len(hello)) / Raw(reply))
    add(out() / up / tcp(flags="A", seq=c_seq + 1 + len(hello), ack=s_seq + 1 + len(reply)))
    add(out() / up / tcp(flags="FA", seq=c_seq + 1 + len(hello), ack=s_seq + 1 + len(reply)))
    add(back() / down / rtcp(flags="FA", seq=s_seq + 1 + len(reply), ack=c_seq + 2 + len(hello)))
    add(out() / up / tcp(flags="A", seq=c_seq + 2 + len(hello), ack=s_seq + 2 + len(reply)))

# 4. A refused connection: SYN to a closed port answered with RST-ACK.
add(out() / IP(src=LAPTOP_IP, dst=ROUTER_IP) / TCP(sport=51515, dport=8080, flags="S", seq=4242), (0.3, 0.5))
add(back() / IP(src=ROUTER_IP, dst=LAPTOP_IP) / TCP(sport=8080, dport=51515, flags="RA", seq=0, ack=4243))

# 5. A second device (phone) does a DNS lookup and a ping.
add(out(PHONE_MAC) / IP(src=PHONE_IP, dst=DNS_SERVER) / UDP(sport=50123, dport=53)
    / DNS(id=7, rd=1, qd=DNSQR(qname="example.com", qtype="AAAA")), (0.2, 0.4))
add(back(PHONE_MAC) / IP(src=DNS_SERVER, dst=PHONE_IP) / UDP(sport=53, dport=50123)
    / DNS(id=7, qr=1, rd=1, ra=1, qd=DNSQR(qname="example.com", qtype="AAAA"),
          an=DNSRR(rrname="example.com", type="AAAA", ttl=300, rdata="2606:2800:220:1::248")))
add(out(PHONE_MAC) / IP(src=PHONE_IP, dst=ROUTER_IP) / ICMP(type=8, id=9, seq=1))
add(back(PHONE_MAC) / IP(src=ROUTER_IP, dst=PHONE_IP) / ICMP(type=0, id=9, seq=1))

# 6. Plain UDP that is not DNS (e.g. a video call / game stream).
for _ in range(3):
    add(out() / IP(src=LAPTOP_IP, dst="203.0.113.50") / UDP(sport=60000, dport=3478) / Raw(random.randbytes(160)))

# 7. IPv6: ping the router over link-local IPv6 (ICMPv6 echo).
for seq in range(1, 3):
    add(out() / IPv6(src=LAPTOP_IP6, dst=ROUTER_IP6) / ICMPv6EchoRequest(id=3, seq=seq), (0.5, 0.9))
    add(back() / IPv6(src=ROUTER_IP6, dst=LAPTOP_IP6) / ICMPv6EchoReply(id=3, seq=seq))

# 8. ICMP "destination unreachable" from the router.
add(back() / IP(src=ROUTER_IP, dst=LAPTOP_IP) / ICMP(type=3, code=3)
    / IP(src=LAPTOP_IP, dst=ROUTER_IP) / UDP(sport=60001, dport=33434), (0.2, 0.4))

if __name__ == "__main__":
    os.makedirs(os.path.dirname(OUTPUT), exist_ok=True)
    wrpcap(OUTPUT, packets)
    print(f"Wrote {len(packets)} packets to {os.path.relpath(OUTPUT, PROJECT_DIR)}")
