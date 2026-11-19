# NetScope – Viva Preparation Guide

## 1. The project in simple words

NetScope is a packet analyzer. We record network traffic with **Wireshark** and save it as a
file. NetScope opens that file, reads every packet with the Python library **Scapy**, works out
which protocols each packet uses (for example IPv4 → UDP → DNS), and shows statistics, charts
and a searchable packet table in a **Streamlit** web dashboard.

It answers questions like: *How many packets were captured? Which computers sent the most
traffic? How much was TCP and how much was UDP? Which websites were looked up with DNS? Were
TCP connections set up properly?*

## 2. Architecture

```
Wireshark  →  .pcap/.pcapng file  →  app.py (upload)
                                        ↓
                               packet_parser.py   (Scapy reads each packet → one metadata row)
                                        ↓  uses
                               protocol_analyzer.py (network / transport / application labels)
                                        ↓
                               Pandas DataFrame (one row = one packet)
                                 ↙                 ↘
                 traffic_statistics.py          filters.py
                 (totals, top IPs, handshakes)  (TCP/UDP/DNS/IP filters)
                                 ↘                 ↙
                               app.py shows the dashboard
```

The key design idea: **the parser runs once** and produces a table of metadata. Every page,
chart and filter works from that table, so all numbers come from the same real packets.

## 3. How packet capturing works

- A network card normally only passes packets addressed to the computer up to the OS.
- A capture driver (**Npcap** on Windows, **libpcap** on Linux) gets a copy of every packet that
  passes through the interface, before the OS processes it.
- Wireshark uses this driver, shows the packets live, and can save them to a file.
- **PCAP** is the older file format: a 24-byte global header, then for each packet a 16-byte
  record header (timestamp, captured length, original length) followed by the packet bytes.
- **PCAPNG** ("next generation") stores data in *blocks* (section header, interface description,
  enhanced packet blocks) and can hold extra information such as comments and several interfaces.
- On Wi-Fi, a normal capture shows only your own computer's traffic plus broadcast/multicast.

## 4. How Scapy parses packets

Scapy knows the format of hundreds of protocol headers. When it reads raw bytes it:

1. Starts with the link-layer type from the file (usually Ethernet).
2. Decodes the Ethernet header (14 bytes). The **EtherType** field says what comes next:
   `0x0800` = IPv4, `0x86DD` = IPv6, `0x0806` = ARP.
3. Decodes the IP header. The **Protocol** field (IPv4) or **Next Header** field (IPv6) says what
   comes next: `6` = TCP, `17` = UDP, `1` = ICMP, `58` = ICMPv6.
4. Decodes TCP/UDP. Scapy then uses port bindings (e.g. port 53 → DNS) to *try* to decode the
   payload. If the bytes don't form a valid header, it leaves them as raw data.

The result is a stack of layer objects, e.g. `Ether / IP / UDP / DNS`. NetScope walks this stack
from the outside in and reads the fields it needs.

## 5. The Python modules

| Module | What it does | Key functions |
|---|---|---|
| `app.py` | Streamlit UI: sidebar navigation, upload, four pages, charts, tables | `handle_upload`, `page_overview`, `page_packet_explorer`, `page_protocol_analysis` |
| `packet_parser.py` | Validates the file (magic number), reads packets with `PcapReader`, builds one metadata dictionary per packet, detects truncated files | `detect_format`, `extract_metadata`, `parse_capture`, `is_truncated` |
| `protocol_analyzer.py` | Decides the network, transport and application protocol of a packet; calculates distributions | `classify_network`, `classify_transport`, `classify_application`, `layer_distributions` |
| `traffic_statistics.py` | Totals, unique IPs, top-5 IPs, TCP flag counts, three-way handshake detection, ICMP and DNS summaries | `summary`, `top_ips`, `find_tcp_handshakes` |
| `filters.py` | Returns a filtered copy of the packet table by protocol and IP | `apply_filters` |

**Error handling:** `extract_metadata` never raises – if a packet is malformed it is still added
(so every packet is counted exactly once) and marked with a `parse_error`. Whole-file problems
raise `CaptureFileError`, which the UI shows as a red message.

## 6. Protocols explained

### TCP – Transmission Control Protocol (transport layer)
- **Connection-oriented** and **reliable**: data arrives complete, in order, without duplicates.
- Uses **sequence numbers** and **acknowledgements**; lost segments are retransmitted.
- Has flow control (window size) and congestion control.
- Header is 20–60 bytes. Used by HTTP/HTTPS, SSH, email.
- **Flags**: SYN (start), ACK (acknowledge), FIN (finish), RST (reset/abort), PSH (push data now), URG.

### UDP – User Datagram Protocol (transport layer)
- **Connectionless**, no guarantee of delivery or order. Very small 8-byte header
  (source port, destination port, length, checksum).
- Faster, lower overhead. Used by DNS, video streaming, online games, VoIP, DHCP.

### DNS – Domain Name System (application layer)
- Translates names like `example.com` to IP addresses.
- Usually over **UDP port 53** (TCP 53 for large responses / zone transfers).
- A **query** has QR bit = 0 and contains the question (name + type, e.g. `A` = IPv4 address,
  `AAAA` = IPv6 address). A **response** has QR = 1 and contains answers.

### ICMP – Internet Control Message Protocol (network layer helper)
- Used for error reporting and diagnostics, not for carrying user data.
- `ping` sends **Echo Request (type 8)** and receives **Echo Reply (type 0)**.
- Other types: Destination Unreachable (3), Time Exceeded (11, used by `tracert`).
- **ICMPv6** does the same for IPv6 and also replaces ARP (Neighbor Discovery).
- ICMP is carried inside IP but has no ports. NetScope lists it with the transport protocols
  because it is the protocol directly above IP.

### ARP – Address Resolution Protocol
- Finds the **MAC address** for an IPv4 address on the local network.
- Request (broadcast): *"Who has 192.168.1.1? Tell 192.168.1.5."*
  Reply (unicast): *"192.168.1.1 is at aa:bb:cc:dd:ee:ff."*
- Works directly over Ethernet – **no IP header, no TCP/UDP**. That is why NetScope shows its
  transport layer as *Not Applicable* and uses ARP's sender/target IP fields as the IP addresses.

## 7. IPv4 vs IPv6

| | IPv4 | IPv6 |
|---|---|---|
| Address size | 32 bits (≈4.3 billion addresses) | 128 bits (≈3.4 × 10³⁸ addresses) |
| Notation | Dotted decimal: `192.168.1.5` | Hexadecimal with colons: `fe80::1` |
| Header | Variable, 20–60 bytes, has checksum | Fixed 40 bytes, no checksum, extension headers |
| Address resolution | ARP | Neighbor Discovery (ICMPv6) |
| Fragmentation | By routers and sender | Only by the sender |
| Configuration | Manual or DHCP | SLAAC or DHCPv6 |
| Broadcast | Yes | No (uses multicast) |

## 8. Source and destination IP addresses

- The **source IP** is the address of the device that sent the packet; the **destination IP** is
  where it should be delivered. Routers forward packets based on the destination IP.
- For a reply, the two are swapped. E.g. ping request `192.168.1.5 → 8.8.8.8`, reply
  `8.8.8.8 → 192.168.1.5`.
- **MAC addresses** change at every hop (they are local to one link); **IP addresses** stay the
  same end to end (except where NAT rewrites them).
- Private ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) are used inside home/college
  networks and translated by NAT to a public IP.

## 9. TCP three-way handshake

```
Client                                  Server
  | ---- SYN        seq = x  ----------->  |   1. "I want to connect, my seq starts at x"
  | <--- SYN, ACK   seq = y, ack = x+1 --  |   2. "OK, my seq starts at y; I got your x"
  | ---- ACK        ack = y+1 ---------->  |   3. "I got your y" → connection ESTABLISHED
```

- It synchronizes the initial sequence numbers of both sides and confirms both can send and receive.
- Connection close uses FIN/ACK in each direction (a four-way close); RST aborts immediately.
- **How NetScope detects it:** it remembers each SYN (by IPs and ports), then looks for a SYN-ACK
  in the reverse direction whose ack = x + 1, then an ACK from the client whose ack = y + 1. All
  three packet numbers are shown on the Protocol Analysis page.

## 10. Why Wireshark?

- Free, open-source and the industry-standard packet capture tool.
- Uses Npcap to capture from any interface and saves standard PCAP/PCAPNG files.
- Separating capture (Wireshark) from analysis (NetScope) means NetScope needs no administrator
  rights or capture drivers, and the same file can be re-analyzed any time.

## 11. Why Scapy?

- Pure Python, so it fits easily with Pandas and Streamlit.
- Reads both PCAP and PCAPNG.
- Decodes many protocols and gives easy access to fields, e.g. `pkt[IP].src`, `pkt[TCP].flags`.
- Writing a parser by hand for every header would be long and error-prone.
- It can also *build* packets, which we use to create synthetic packets for the automated tests.

## 12. Limitations

- Offline only (no live capture).
- Only DNS is identified at the application layer; HTTP/TLS are not guessed from ports.
- Encrypted payloads cannot be read (and NetScope does not show payloads anyway).
- No IP fragment or TCP stream reassembly.
- Scapy is slow for large files, so uploads are limited to 25 MB.

---

## 13. Likely Viva Questions and Answers

**1. What is a packet?**
A small unit of data sent over a network. It has headers (addressing and control information for
each layer) and a payload (the actual data).

**2. What is packet sniffing / packet capture?**
Recording copies of packets passing through a network interface for analysis, using a driver such
as Npcap or libpcap.

**3. What is the difference between PCAP and PCAPNG?**
Both store captured packets. PCAP is simpler: one global header and a record header per packet.
PCAPNG stores blocks and supports multiple interfaces, comments and more metadata. Wireshark saves
PCAPNG by default.

**4. How does NetScope know a file is a valid capture?**
It checks the first 4 bytes (magic number): `D4 C3 B2 A1` / `A1 B2 C3 D4` (and nanosecond
variants) for PCAP, `0A 0D 0D 0A` for PCAPNG. Anything else is rejected.

**5. Explain the TCP/IP layers that NetScope classifies.**
Link layer (Ethernet – MAC addresses), network layer (IPv4/IPv6/ARP – logical addressing and
routing), transport layer (TCP/UDP – ports, process-to-process delivery) and application layer
(DNS etc.).

**6. Why do you keep three separate protocol distributions?**
A DNS packet is IPv4 *and* UDP *and* DNS at the same time. Putting all in one chart would count
it three times. Separate per-layer distributions each add up to the total number of packets.

**7. Difference between TCP and UDP?**
TCP is connection-oriented, reliable, ordered, with flow and congestion control (20+ byte header).
UDP is connectionless, unreliable, with an 8-byte header but lower delay.

**8. What is a port number?**
A 16-bit number (0–65535) that identifies the application/process on a host. Well-known ports
0–1023 (e.g. 53 DNS, 80 HTTP, 443 HTTPS), registered 1024–49151, dynamic/ephemeral 49152–65535
(used by clients).

**9. Why don't ICMP and ARP packets have ports?**
Ports belong to TCP and UDP. ICMP sits directly on IP and uses type/code fields; ARP sits
directly on Ethernet and has no IP or transport header at all.

**10. Why not identify DNS just by port 53?**
Any program can send any data on port 53. NetScope counts a packet as DNS only when Scapy
successfully decodes a valid DNS header (valid opcode and the number of questions matches the
header). Our tests include random bytes on port 53 that are correctly *not* counted as DNS.

**11. Why is traffic on port 443 not shown as HTTPS/TLS?**
Port numbers are only conventions. Without parsing a real TLS header we cannot be sure, so it is
shown as *Other / Not Detected* rather than giving a possibly wrong answer.

**12. What happens during `ping`?**
The computer sends an ICMP Echo Request (type 8); the target answers with an Echo Reply
(type 0). The time between them is the round-trip time.

**13. What is ARP and why is it needed?**
IP addresses identify hosts logically, but Ethernet delivers frames using MAC addresses. ARP
finds the MAC address for an IP address on the local network using a broadcast request and a
unicast reply.

**14. What replaces ARP in IPv6?**
Neighbor Discovery Protocol, which uses ICMPv6 Neighbor Solicitation and Neighbor Advertisement
messages.

**15. Explain the three-way handshake.**
Client sends SYN (seq = x); server replies SYN-ACK (seq = y, ack = x+1); client sends ACK
(ack = y+1). Both sides now know each other's starting sequence numbers and the connection is
established.

**16. Why does TCP use random initial sequence numbers?**
To avoid confusing packets from old connections with new ones, and to make it hard for an attacker
to guess sequence numbers and inject data.

**17. What is the difference between a MAC address and an IP address?**
MAC: 48-bit hardware address, used on the local link, changes at each hop. IP: logical address
(32-bit IPv4 or 128-bit IPv6), used end to end for routing.

**18. What is a DNS query vs a DNS response?**
Both use the same message format. The QR bit is 0 for a query and 1 for a response. The query has
the question section (domain and type); the response repeats the question and adds answer records.

**19. What does "Total Captured Data Size" mean?**
The sum of the captured length of all packets, i.e. the bytes Wireshark saved for each frame
(headers included, as seen on the wire).

**20. What does "Other / Not Detected" mean? Is it the same as zero?**
No. *Zero* means no packets of that protocol were present. *Other / Not Detected* means packets
existed but their protocol at that layer was not one we identify (e.g. IGMP over IPv4) or could
not be decoded. NetScope shows both separately, including categories with a count of 0.

**21. How do you handle malformed packets or corrupted files?**
Each packet is decoded inside a try/except: a bad packet is still counted, labelled
*Other / Not Detected* and marked with an error note. Empty files, non-capture files and files with
broken headers raise a clear error message. A file cut off in the middle of a packet is analyzed
up to that point with a warning.

**22. Do filters change the dashboard statistics?**
No. Filters return a new copy of the packet table; the original table used for the Overview and
Protocol Analysis pages is never modified. This is checked by an automated test.

**23. Why is live capture not implemented?**
Live capture requires administrator rights and the Npcap driver, and depends on the operating
system. Offline analysis keeps the project simple, safe and repeatable – the same file always gives
the same results.

**24. How did you test the project?**
With pytest. Scapy is used to build synthetic packets (IPv4 TCP, UDP, ICMP echo request/reply,
ARP, DNS query, IPv6, ICMPv6, unsupported protocol, frame without a network layer, fake DNS on port
53, truncated TCP header). We also test empty, invalid, header-only and truncated files in both
PCAP and PCAPNG formats, statistics, filters and handshake detection. Synthetic packets are only
used in tests, never shown as real traffic.

**25. Is it legal/ethical to capture network traffic?**
Only on networks you own or have permission to analyze. Capturing other people's traffic without
permission can violate privacy laws and institutional rules. NetScope also avoids showing payload
contents.

**26. What is the difference between captured length and original length?**
Original (wire) length is the real size of the packet; captured length is how much was saved. They
differ if Wireshark was set to save only the first N bytes (snap length).

**27. What is the TTL / Hop Limit field?**
A counter in the IPv4 (TTL) and IPv6 (Hop Limit) header that each router decreases by 1. When it
reaches 0 the packet is dropped and an ICMP Time Exceeded message is sent. It prevents packets from
looping forever, and `tracert` uses it to discover the route.

**28. Why is one IP address usually at the top of both "Top Source" and "Top Destination"?**
In a capture taken on your own computer, almost every packet is either sent by or sent to your
computer, so your own IP address appears most often in both lists.

**29. What is the role of Pandas in this project?**
After parsing, every packet's metadata is one row in a DataFrame. Pandas makes counting
(`value_counts`), filtering (boolean masks) and displaying tables simple and fast.

**30. What would you add in the future?**
HTTP/TLS detection by real header parsing, a conversations/flows table, a traffic-over-time chart,
TCP retransmission analysis, CSV export and optional live capture.
