# NetScope Explained: The Complete Guide

This guide explains **everything** about NetScope in simple words: the networking theory,
the sample demo file, every screen of the app, and how the code works.

Most examples use the built-in demo file **`sample_data/sample_capture.pcap`**, so you can
open the app, switch on **Use sample capture**, and see every number in this guide on your
own screen. The newer features (HTTP and TLS detection, retransmissions, round-trip time)
are shown with a second demo file, **`sample_data/web_demo_capture.pcap`**, which you pick
from the drop-down under the same switch (section 5.5).

---

## Contents

1. [NetScope in one minute](#1-netscope-in-one-minute)
2. [Networking basics you need first](#2-networking-basics-you-need-first)
3. [The protocols, one by one (with real packets)](#3-the-protocols-one-by-one-with-real-packets)
4. [Capture files: Wireshark, PCAP and PCAPNG](#4-capture-files-wireshark-pcap-and-pcapng)
5. [The sample demo files](#5-the-sample-demo-files)
6. [Walkthrough of the app using the sample](#6-walkthrough-of-the-app-using-the-sample)
7. [How the code works](#7-how-the-code-works)
8. [Packet sizes: where every byte comes from](#8-packet-sizes-where-every-byte-comes-from)
9. [Running, testing and rebuilding the sample](#9-running-testing-and-rebuilding-the-sample)
10. [Limitations and future improvements](#10-limitations-and-future-improvements)
11. [Quick viva answers](#11-quick-viva-answers)
12. [Glossary](#12-glossary)

---

## 1. NetScope in one minute

**What it is:** NetScope is a web dashboard that opens a network capture file (made with
Wireshark), reads every packet inside it, and shows you, in plain charts and tables,
*who talked to whom, using which protocols, and how*.

**An analogy:** think of the internet as a postal system.

| Postal system | Network |
|---|---|
| A letter | A **packet** |
| The envelope's address | The **IP address** |
| The house's door number | The **port** number |
| A pile of letters collected in a sack | A **capture file** (.pcap) |
| A person who reads every envelope and makes a report | **NetScope** |

NetScope reads only the **envelopes** (headers). It never opens or displays what is inside
the letters (payloads). That is a privacy rule built into the project.

**The three steps:**

```
 1. CAPTURE              2. ANALYZE                     3. VISUALIZE
 Wireshark records  -->  Scapy decodes each packet, -->  Streamlit shows charts,
 packets into a          NetScope extracts header        tables and packet
 .pcap / .pcapng file    data and computes statistics    details in the browser
```

**Technologies used:**

| Tool | Job in this project |
|---|---|
| **Wireshark** | Captures real traffic and saves it to a file |
| **Python** | The programming language |
| **Scapy** | Python library that decodes packet bytes into layers (Ethernet → IP → TCP…) |
| **Pandas** | Stores all packets as a table (DataFrame) and does counting/statistics |
| **Streamlit** | Turns the Python script into a web dashboard |
| **Altair** | Draws the bar charts and the traffic-over-time chart |
| **pytest** | Runs the automated tests |

---

## 2. Networking basics you need first

### 2.1 What is a packet?

Data on a network is never sent in one big piece. It is cut into small pieces called
**packets**. Each packet has:

- a **header**: control information (who sent it, who should receive it, what type it is);
- a **payload**: the actual data (part of a web page, a message, etc.).

Think of the header as the envelope and the payload as the letter.

### 2.2 Layers: the TCP/IP model

Networking is split into **layers**. Each layer has one job and adds its own header.

| # | TCP/IP layer | OSI equivalent | Job | Protocols in NetScope | Address used |
|---|---|---|---|---|---|
| 4 | **Application** | Layers 5–7 | What the user's program wants | DNS (and HTTP/TLS, not decoded) | Domain names |
| 3 | **Transport** | Layer 4 | Delivery between *programs* | TCP, UDP | **Port** numbers |
| 2 | **Network (Internet)** | Layer 3 | Delivery between *computers* across networks | IPv4, IPv6, ICMP, ICMPv6 | **IP** addresses |
| 1 | **Link** | Layers 1–2 | Delivery to the *next device* on the same network | Ethernet, ARP | **MAC** addresses |

> ICMP technically sits inside IP (it is a "helper" of the network layer), but NetScope
> shows it in the **transport layer** column, because it is the protocol that comes directly
> after the IP header, in the same position where TCP or UDP would be.

### 2.3 Encapsulation: layers inside layers

When a program sends data, each layer **wraps** the data from the layer above with its own
header, like putting an envelope inside a bigger envelope:

```
+------------------+-------------+-------------+------------------------+
| Ethernet header  | IP header   | TCP header  | Payload (data)         |
| 14 bytes         | 20 bytes    | 20 bytes    | e.g. 220 bytes         |
| MAC addresses    | IP addresses| Ports, flags|                        |
+------------------+-------------+-------------+------------------------+
  Link layer         Network       Transport     Application
```

The receiver unwraps it in the reverse order. Scapy does exactly this unwrapping for us:
it reads the raw bytes and gives back the layers `Ether / IP / TCP / Raw`.

### 2.4 The three kinds of address

| Address | Example from the sample | Layer | Scope |
|---|---|---|---|
| **MAC address** | `02:00:00:00:00:10` | Link | Only the local network (your Wi-Fi). Burned into the network card. |
| **IP address** | `192.168.1.10`, `8.8.8.8`, `fe80::10` | Network | The whole internet. Identifies a computer. |
| **Port number** | `443`, `53`, `56299` | Transport | Inside one computer. Identifies a program/service. |

**Analogy:** IP address = the building, port = the flat number, MAC address = the name on
the door of the next room you pass through.

### 2.5 Private vs public IP addresses

- `192.168.x.x`, `10.x.x.x`, `172.16–31.x.x` are **private**: used inside homes and offices,
  not reachable from the internet. In the sample, the laptop (`192.168.1.10`), phone
  (`192.168.1.23`) and router (`192.168.1.1`) are private.
- Everything else (e.g. `8.8.8.8`, `93.184.216.34`) is **public**: reachable on the internet.
- `fe80::...` is an IPv6 **link-local** address: valid only on the local link.
- `203.0.113.x` is a range reserved for **documentation/examples**.

### 2.6 Ports

A port number (0–65535) tells the computer **which program** should receive the data.

| Port | Service | Seen in the sample? |
|---|---|---|
| 53 | DNS | Yes, all DNS packets |
| 80 | HTTP (web, unencrypted) | No |
| 443 | HTTPS (web, encrypted with TLS) | Yes, the 4 website connections |
| 8080 | Alternative web port | Yes, the refused connection |
| 3478 | STUN (used by video calls) | Yes, the plain UDP packets |
| 49152–65535 | **Ephemeral** ports, picked randomly by the client | Yes, e.g. `56299`, `62779` |

The server listens on a fixed, well-known port (443). The client uses a random, temporary
port (56299) so it can run many connections at the same time.

---

## 3. The protocols, one by one (with real packets)

Each protocol below is explained with packets you can find in the **Packet Explorer** by
typing the packet number.

### 3.1 Ethernet (link layer)

- Carries every packet across the local network (cable or Wi-Fi).
- Header: **destination MAC**, **source MAC**, and a type field saying what is inside
  (IPv4, IPv6 or ARP).
- Header size: **14 bytes**.

In the sample, every packet travels between the devices and the router
(`02:00:00:00:00:01`). The special MAC **`ff:ff:ff:ff:ff:ff`** means **broadcast**:
"everyone on this network".

### 3.2 ARP: Address Resolution Protocol

**Problem it solves:** to send a packet on the local network you need the receiver's **MAC**
address, but you usually only know its **IP** address. ARP finds the MAC for an IP.

**Sample packets 1–2:**

| No. | From → To | ARP operation | Meaning |
|---|---|---|---|
| 1 | `192.168.1.10` → `192.168.1.1` (MAC `ff:ff:ff:ff:ff:ff`) | Request (who-has) | "Who has 192.168.1.1? Tell 192.168.1.10." Sent to **everyone** (broadcast). |
| 2 | `192.168.1.1` → `192.168.1.10` | Reply (is-at) | "192.168.1.1 is at MAC 02:00:00:00:00:01." Sent directly back. |

Key facts:
- ARP has **no IP header and no transport layer**. That is why NetScope shows its transport
  layer as **"Not Applicable"**.
- NetScope shows the IP addresses written *inside* the ARP message as source/destination IP.
- Size: 14 (Ethernet) + 28 (ARP) = **42 bytes**.

### 3.3 IPv4: Internet Protocol version 4

- Delivers packets between computers across networks, using **32-bit** addresses written
  as four numbers: `192.168.1.10`.
- About 4.3 billion addresses in total, which have run out. NAT (routers sharing one public IP) is
  the workaround.
- Header size: usually **20 bytes**. Contains source IP, destination IP, TTL (hop limit),
  and the protocol number of what is inside (1 = ICMP, 6 = TCP, 17 = UDP).
- In the sample: **66 of 72 packets (91.67%)** are IPv4.

### 3.4 IPv6: Internet Protocol version 6

- The successor of IPv4, with **128-bit** addresses written in hexadecimal: `fe80::10`.
  (`::` means "a run of zeros".)
- Enough addresses for every device on Earth, many times over. No NAT needed.
- Fixed header size: **40 bytes**.
- In the sample: packets **68–71** are IPv6 pings between the laptop (`fe80::10`) and the
  router (`fe80::1`). That is **4 packets (5.56%)**.

| | IPv4 | IPv6 |
|---|---|---|
| Address size | 32 bits | 128 bits |
| Example | `192.168.1.10` | `fe80::10` |
| Header | 20 bytes (variable) | 40 bytes (fixed) |
| Address resolution | ARP | NDP (part of ICMPv6) |
| Ping protocol | ICMP | ICMPv6 |

### 3.5 ICMP: Internet Control Message Protocol

ICMP carries **control and error messages** for IP. It has **no ports**. It uses a
**type** and **code** instead.

| Type | Name | Meaning |
|---|---|---|
| 8 | echo-request | "Are you there?" (sent by `ping`) |
| 0 | echo-reply | "Yes, I'm here." |
| 3 | dest-unreach | "I could not deliver your packet." (the code says why) |

**Sample, ping (packets 3–10):** the laptop pings Google's DNS server `8.8.8.8` four times.
Each request (odd number) gets a reply (even number) about 15–30 ms later. This is exactly
what you see when you type `ping 8.8.8.8` in a terminal.

**Sample, phone ping (packets 63–64):** the phone `192.168.1.23` pings the router.

**Sample, destination unreachable (packet 72):** the router tells the laptop that a UDP
packet could not be delivered (type 3, code 3 = *port unreachable*). This packet is special:
inside it there is a **copy of the original IP + UDP header** that failed. NetScope
correctly reports it as **ICMP**, not UDP, because it reads the **outermost** layers first
(see [7.4](#74-protocol_analyzerpy-classifying-every-packet)).

Total ICMP in the sample: 8 (laptop ping) + 2 (phone ping) + 1 (unreachable) = **11**.

### 3.6 ICMPv6

The IPv6 version of ICMP. It does ping (`Echo Request` / `Echo Reply`) and also replaces
ARP for IPv6 (Neighbor Discovery).
Sample: packets **68–71**, two echo requests and two echo replies.

### 3.7 TCP: Transmission Control Protocol

TCP gives **reliable, ordered** delivery. It is used by the web, email, file transfer, etc.

**How TCP is reliable:**
1. **Connection first:** a three-way handshake before any data is sent.
2. **Sequence numbers:** every byte is numbered, so the receiver can put data in order.
3. **Acknowledgements (ACK):** the receiver confirms what it got; lost data is resent.
4. **Proper close:** both sides say goodbye with FIN.

**TCP flags**: single bits in the header that say what a packet is for:

| Flag | Name | Meaning |
|---|---|---|
| SYN | Synchronize | "I want to start a connection" |
| ACK | Acknowledge | "I received your data up to this number" |
| PSH | Push | "Deliver this data to the program now" |
| FIN | Finish | "I have finished sending, let's close" |
| RST | Reset | "Abort! This connection is refused or broken" |

#### A full TCP conversation from the sample (laptop ↔ example.com, packets 13–22)

```
 Laptop 192.168.1.10:56299                         Server 93.184.216.34:443
        |                                                     |
 #13    | ---- SYN        seq=5194038 ----------------------> |  1. "Let's connect"
 #14    | <--- SYN, ACK   seq=5541484  ack=5194039 ---------- |  2. "OK, let's connect"
 #15    | ---- ACK        seq=5194039  ack=5541485 ---------> |  3. "Great, connected!"
        |                                                     |
 #16    | ---- PSH, ACK   220 bytes of data ----------------> |  request
 #17    | <--- ACK        ack=5194259 (=5194039+220) -------- |  "got your 220 bytes"
 #18    | <--- PSH, ACK   1200 bytes of data ---------------- |  response
 #19    | ---- ACK        ack=5542685 (=5541485+1200) ------> |  "got your 1200 bytes"
        |                                                     |
 #20    | ---- FIN, ACK --------------------------------------> |  "I'm done"
 #21    | <--- FIN, ACK --------------------------------------- |  "Me too"
 #22    | ---- ACK -------------------------------------------> |  "Bye"
```

#### The three-way handshake (most important viva topic)

| Step | Packet | Flags | Rule |
|---|---|---|---|
| 1 | #13 client → server | SYN | Client picks a random starting number `x` = **5194038** |
| 2 | #14 server → client | SYN, ACK | Server picks its own `y` = **5541484** and replies `ack = x + 1` = **5194039** |
| 3 | #15 client → server | ACK | Client replies `ack = y + 1` = **5541485** |

Why "+1"? The SYN itself counts as one byte of sequence space, so acknowledging it means
"I expect your **next** number".

Why random starting numbers? So old packets from a previous connection cannot be confused
with a new one, and to make attacks (guessing numbers) harder.

The acknowledgement number always means **"the next byte I expect from you"**. That's why
after the server receives 220 bytes starting at 5194039, it says `ack = 5194039 + 220 = 5194259`.

#### A refused connection (packets 59–60)

The laptop sends **SYN** to the router on port **8080**, but nothing is listening there.
The router answers **RST, ACK**: "connection refused". No handshake happens.
That's why the sample has **5 SYN** packets but only **4 SYN, ACK**, and **4 completed
handshakes**.

#### TCP numbers in the sample

- 4 websites × 10 packets each = 40, plus the refused connection (2) = **42 TCP packets**.
- Flag counts: ACK 16 · PSH,ACK 8 · FIN,ACK 8 · SYN 5 · SYN,ACK 4 · RST,ACK 1 (total 42).

### 3.8 UDP: User Datagram Protocol

UDP is the opposite of TCP: **no connection, no handshake, no acknowledgement, no
guarantee**. It just sends. The header is tiny (**8 bytes**: ports, length, checksum).

**Why use it?** It is fast and simple. Perfect when speed matters more than perfection:
DNS lookups, video calls, online games, live streaming. A lost video frame is better
skipped than resent late.

| | TCP | UDP |
|---|---|---|
| Connection | Yes (handshake) | No |
| Reliable | Yes (ACK + resend) | No |
| Ordered | Yes (sequence numbers) | No |
| Header | 20 bytes | 8 bytes |
| Used for | Web, email, files | DNS, video calls, games |
| Sample packets | 42 | 13 |

**Sample UDP:** 10 DNS packets + 3 plain UDP packets (65–67), which are the laptop sending
data to `203.0.113.50` port 3478, like a video-call stream. Notice: **no reply and no
handshake**. That is normal for UDP.

### 3.9 DNS: Domain Name System

Computers talk using IP addresses, but humans remember names. **DNS translates names into
IP addresses**, like a phone book.

- Runs over **UDP port 53** (usually).
- A **query** asks a question; a **response** gives the answer.
- Common record types: **A** = IPv4 address, **AAAA** = IPv6 address.

**Sample, DNS then connect (packets 11–15):**

```
 #11  laptop -> 8.8.8.8      DNS Query     "What is the IP of example.com?" (type A)
 #12  8.8.8.8 -> laptop      DNS Response  "example.com is 93.184.216.34"
 #13  laptop -> 93.184.216.34  TCP SYN     the laptop now connects to that IP
```

This is what happens every time you type a website name: **DNS first, then TCP**. The
sample repeats this for `example.com`, `wikipedia.org`, `github.com` and `python.org`.

**Sample, AAAA query (packets 61–62):** the phone asks for the **IPv6** address of
`example.com` (type **AAAA**). That's why `example.com` was queried **2 times** in the
"Top queried DNS domains" table.

**DNS packets in total:** 5 queries + 5 responses = **10**.

### 3.10 HTTP: the web's request/response protocol

**HTTP** (HyperText Transfer Protocol) runs over TCP, usually on port **80**. HTTP/1.x is
plain text: the browser sends a **request**, the server sends back a **response**.

```
 Request (browser -> server)          Response (server -> browser)
 GET /index.html HTTP/1.1             HTTP/1.1 200 OK
 Host: example.com                    Content-Type: text/html
 User-Agent: ...                      Content-Length: 35
 (blank line)                         (blank line)
                                      <html>...  (the body)
```

- The first line of a request is the **request line**: *method* (GET, POST, …), *path*
  (`/index.html`) and *version*. The **Host** header names the website, because one server
  can host many sites on the same IP address.
- The first line of a response is the **status line**: version, a 3-digit **status code**
  and a reason phrase (`200 OK`, `404 Not Found`, `301 Moved Permanently`).

**How NetScope detects HTTP:** it looks at the first bytes of the TCP payload. The packet is
labeled HTTP only if the first line is a well-formed request line (a known method, a path and
`HTTP/1.0` or `HTTP/1.1`) or a well-formed status line (`HTTP/1.x` followed by a code from
100 to 599). NetScope keeps only the request line, the Host header and the status. The body
is never stored. Because it reads the content, HTTP on an unusual port (e.g. 8080) is still
found, and text such as `GETTING started…` is **not** mistaken for HTTP.

### 3.11 HTTPS and TLS: encryption, and what can still be seen

**HTTPS** is HTTP sent inside an encrypted **TLS** (Transport Layer Security) connection,
usually on port **443**. Nobody in between can read the pages, but the start of the
connection, the **TLS handshake**, still has readable headers.

Every TLS message travels in a **record** with a 5-byte header:

| Byte(s) | Field | Values |
|---|---|---|
| 1 | Content type | 20 Change Cipher Spec · 21 Alert · **22 Handshake** · 23 Application Data |
| 2 | Version | `3,1` = TLS 1.0 … `3,3` = TLS 1.2 (TLS 1.3 also writes `3,3` here) |
| 2 | Length | size of the record that follows |

The TLS 1.3 handshake, as seen in a capture:

```
 Client                                           Server
   | --- Client Hello (SNI = www.wikipedia.org) ---> |   readable
   | <-- Server Hello + Change Cipher Spec + ...  --- |   Server Hello readable,
   |                                                  |   the rest is encrypted
   | <========= Application Data (encrypted) =======> |   unreadable
```

- The **Client Hello** carries the **SNI** (Server Name Indication) extension: the name of the
  website the client wants (e.g. `www.wikipedia.org`), so a server with many sites can pick
  the right certificate. The SNI is sent *before* encryption starts, so it is visible.
- Which version is really used? TLS 1.3 keeps writing "TLS 1.2" in old fields for
  compatibility. The real versions are in the **supported_versions** extension. The client
  lists what it supports and the server's Server Hello names the one chosen.

**How NetScope detects TLS:** a packet is labeled TLS only if its TCP payload starts with a
valid record header (content type 20–23, version 3.x, a sensible length). NetScope then reads
the record types (e.g. "Server Hello, Change Cipher Spec, Application Data"), the version
from the Hello's supported_versions extension, and the SNI from a Client Hello. When there is
no Hello, only the record header's version is known, so it is shown as
"TLS 1.2 (record layer)", the same way Wireshark does. The encrypted data is never stored.

**Why the 40 port-443 packets in the mixed sample are still "Other / Not Detected":** the
synthetic file was built with **random bytes** as payload, not real TLS records. Their first
byte is not 20–23, so they fail the record-header check. NetScope's rule is: **only label a
protocol if its header was actually decoded, never guess from the port number.** A packet
on port 443 *could* be something else, and here it really is.

### 3.12 TCP reliability in practice: retransmission and round-trip time

**Retransmission.** If a segment gets no acknowledgement in time, TCP assumes it was lost
and **sends it again**, with the **same sequence number**. In a capture you therefore see two
packets with the same sequence number and the same data, going the same way.

```
 Client                                  Server
   | ---- data  seq=4180257615 (425 B) ---> X   lost
   |                    ... about 300 ms, no ACK ...
   | ---- data  seq=4180257615 (425 B) ---> |   retransmission: same seq, same size
   | <--- ACK   ack=4180258040 ------------ |   = 4180257615 + 425
```

**Round-trip time (RTT)** is the time from sending a segment until its acknowledgement
comes back. TCP measures it to decide how long to wait before retransmitting.

**Karn's algorithm:** if a segment was sent twice and then acknowledged, you cannot tell
whether the ACK answers the first copy or the second, so that measurement is thrown away.

**Where the capture is taken matters.** On the client, "client sends → server ACKs" is a
full trip across the network (tens of milliseconds). "Server sends → client ACKs" is just
how quickly the client's own computer replied (often under 1 ms).

---

## 4. Capture files: Wireshark, PCAP and PCAPNG

### 4.1 How capturing works

Normally a network card ignores packets not meant for it. A capture tool (Wireshark) puts
the card in a mode where it hands **a copy of every packet** to the program. On Windows,
the **Npcap** driver does this. Wireshark then saves the packets to a file.

NetScope does **not** capture. It only **reads saved files**, so it doesn't need Npcap or
administrator rights. This is called **offline analysis**.

### 4.2 The two file formats

| | PCAP | PCAPNG ("next generation") |
|---|---|---|
| Age | Classic, very old, simple | Newer, Wireshark's default |
| Structure | 24-byte file header, then for each packet a 16-byte record header + packet bytes | A list of "blocks", each with its own length |
| Extra info | None | Interface names, comments, multiple interfaces |
| First 4 bytes ("magic number") | `d4 c3 b2 a1` (or variants) | `0a 0d 0d 0a` |

NetScope checks the **magic number** (the first 4 bytes) to know which format a file is.
If the bytes match neither, it shows a friendly error instead of crashing. The sample file
is **PCAP** format.

### 4.3 Packet timestamps

Every packet in the file has the exact time it was captured (to the microsecond). NetScope
shows it as a readable date and also as **"time since first packet"**, which makes it easy
to see delays, e.g. the ping replies arrive 15–30 ms after the requests.

---

## 5. The sample demo files

### 5.1 Why a synthetic file?

A real capture from your own network contains private data (websites you visit, device
addresses), and you may not be allowed to capture on the college network. So the demo file
is **synthetic**: every packet was **constructed in Python with Scapy**, following the
real protocol rules. It looks exactly like a real capture to Wireshark and to NetScope, but
contains **no real traffic**. It is safe to share, commit to GitHub and show to anyone.

- File: `sample_data/sample_capture.pcap` (PCAP format, 72 packets, 10.12 KB of packet data,
  10.47 seconds long)
- Made by: `tools/make_sample_capture.py`. Run it again and you get the **same file**
  (the random generator uses a fixed seed).
- You can also open this file in **Wireshark** to compare with NetScope.

### 5.2 The imaginary network

```
                            INTERNET
     8.8.8.8 (DNS)   93.184.216.34 (example.com)   208.80.154.224 (wikipedia.org)
     140.82.112.3 (github.com)   151.101.0.223 (python.org)   203.0.113.50 (call server)
                               |
                     +---------+---------+
                     |  Router           |  192.168.1.1  /  fe80::1
                     |  MAC ..:00:01     |
                     +----+---------+----+
                          |         |
               +----------+--+   +--+-----------+
               | Laptop      |   | Phone        |
               | 192.168.1.10|   | 192.168.1.23 |
               | fe80::10    |   | MAC ..:00:23 |
               | MAC ..:00:10|   +--------------+
               +-------------+
```

### 5.3 The story of the 72 packets

The file tells a short story, in 8 scenes:

| Scene | Packets | What happens | Protocols shown |
|---|---|---|---|
| 1 | 1–2 | Laptop asks "who is the router?" and gets its MAC | ARP (request + reply) |
| 2 | 3–10 | Laptop runs `ping 8.8.8.8` four times | ICMP echo request/reply |
| 3 | 11–22 | Look up **example.com**, connect, exchange data, close | DNS + full TCP connection |
| 3 | 23–34 | Same for **wikipedia.org** | DNS + TCP |
| 3 | 35–46 | Same for **github.com** | DNS + TCP |
| 3 | 47–58 | Same for **python.org** | DNS + TCP |
| 4 | 59–60 | Laptop tries port 8080 on the router: **refused** | TCP SYN → RST |
| 5 | 61–64 | The **phone** looks up example.com (IPv6/AAAA) and pings the router | DNS AAAA, ICMP |
| 6 | 65–67 | Laptop streams 3 UDP packets (like a video call) | Plain UDP |
| 7 | 68–71 | Laptop pings the router over **IPv6** | IPv6, ICMPv6 |
| 8 | 72 | Router reports "port unreachable" | ICMP type 3 |

Each website visit (scene 3) is **12 packets**: 2 DNS + 3 handshake + 4 data/ACK +
3 close.

### 5.4 Sample facts at a glance

| Fact | Value |
|---|---|
| Total packets | 72 |
| Total captured data | 10,361 bytes = **10.12 KB** |
| Duration | 10.47 seconds |
| Unique source IPs | 10 |
| Unique destination IPs | 11 |
| DNS packets | 10 |
| Completed TCP handshakes | 4 |
| HTTP / TLS packets | 0 / 0 (the port-443 payloads are random bytes, see 3.11) |
| Retransmissions | 0 |
| Malformed packets | 0 |

### 5.5 The second demo file: web traffic

`sample_data/web_demo_capture.pcap` (built by `tools/make_web_demo_capture.py`) is also
completely synthetic. It exists to show the HTTP, TLS, retransmission and RTT features,
which the mixed sample does not contain. The same laptop (`192.168.1.10`) does three things:

| Packets | What happens |
|---|---|
| 1–4 | DNS lookups: `example.com` → 93.184.216.34 and `www.wikipedia.org` → 208.80.154.224 |
| 5–7 | TCP handshake with example.com on **port 80**. The server answers after **42 ms** |
| 8 | **HTTP request** `GET /index.html`, `Host: example.com` (87 bytes of payload) |
| 9 | Server ACKs the request |
| 10 | **HTTP response** `200 OK`, but this copy is "lost" (the laptop never ACKs it) |
| 11 | The server **retransmits** the response **300 ms** later: same seq 1921578, same 99 bytes |
| 12–15 | Laptop ACKs it. Connection closes with FIN / FIN / ACK |
| 16–18 | TCP handshake with wikipedia.org on **port 443**. The server answers after **65 ms** |
| 19 | **TLS Client Hello** with SNI `www.wikipedia.org`, offering TLS 1.3 |
| 20 | **Server Hello** (chooses TLS 1.3) + Change Cipher Spec + encrypted data, in one segment |
| 21 | Client's Change Cipher Spec + encrypted Finished |
| 22 | Client's encrypted request (425 bytes), which is "lost" |
| 23 | Server ACKs only up to packet 21 |
| 24 | The laptop **retransmits** packet 22, **313 ms** later: same seq 4180257615, same 425 bytes |
| 25–29 | Server ACKs it and sends three encrypted records (1205 + 1205 + 645 bytes). The laptop ACKs |
| 30–32 | Connection closes |

| Fact | Value |
|---|---|
| Total packets | 32 (6,493 bytes, 1.85 s) |
| Application layer | DNS 4 · HTTP 3 · TLS 8 · Other / Not Detected 17 |
| Handshakes (RTT) | 2 (42 ms to example.com, 65 ms to wikipedia.org) |
| Retransmissions | 2 (packet 11 = copy of 10, packet 24 = copy of 22) |
| HTTP requests | 1: `GET /index.html`, Host `example.com`, reply `200 OK` |
| TLS server names | `www.wikipedia.org` (1 Client Hello) |

Why are packets 9, 23 and the handshakes "Other / Not Detected" at the application layer?
They are pure TCP control packets **with no payload**, so there is no HTTP or TLS header to
read. HTTP and TLS are labeled per packet, only where their header actually is.

---

## 6. Walkthrough of the app using the sample

Start the app (`python -m streamlit run app.py`), open <http://localhost:8501>, and switch on
**Use sample capture** in the sidebar.

### 6.1 Sidebar

- **Navigation:** *Overview*, *Packet Explorer*, *Protocol Analysis* (the "Analyze"
  group) and *About*.
- **Capture file:** drag-and-drop box for your own `.pcap` / `.pcapng` (max 25 MB).
- **Use sample capture:** loads a demo file. A drop-down under the switch chooses
  **Mixed protocols (72 packets)** or **Web traffic: HTTP, TLS, retransmissions**. An
  uploaded file always wins over the sample. The choice is kept in the URL (`?demo=1` for
  the mixed file, `?demo=web` for the web file), so a page refresh keeps it.
- **Active capture card:** file name, packet count, format and a green *Demo* badge
  for the sample.

### 6.2 Overview page

**The five tiles:**

| Tile | Sample value | How it is calculated | Why this number |
|---|---|---|---|
| Packets analyzed | **72** | Number of rows in the packet table | One row per packet in the file |
| Captured data | **10.12 KB** | Sum of all packet lengths ÷ 1024 | 10,361 bytes ÷ 1024 = 10.12 |
| Source IPs | **10** | Count of different source IPs | Laptop, phone, router, 8.8.8.8, 4 websites, and 2 IPv6 addresses |
| Destination IPs | **11** | Count of different destination IPs | Same 10 + `203.0.113.50`, which only *receives* UDP and never replies |
| DNS packets | **10** | Packets whose DNS header was decoded | 5 queries + 5 responses |

The chips at the top right show the file name and the time span (**10.47 s**).

**Traffic over time:** a step chart of how many packets (or, with the **Bytes** button,
how many bytes) were captured in each time interval. The interval is chosen automatically
so the chart has at most about 40 steps: **0.5 s** for the 10.47 s sample (21 intervals),
**0.05 s** for the 1.85 s web demo. Empty intervals are kept at 0, so pauses in the traffic
are visible. In the sample, the busy part from about 4.5 s to 8 s is the four website
visits. In the web demo, the gaps at 0.40–0.65 s and 1.05–1.25 s are the two waits
before the retransmissions.

**Protocol distribution:** three charts, one per layer. Each packet is counted **once in
each chart**, so every chart adds up to 72:

| Layer | Sample result | Adds up to |
|---|---|---|
| Network | IPv4 66 · IPv6 4 · ARP 2 · Other 0 | 72 |
| Transport | TCP 42 · UDP 13 · ICMP 11 · ICMPv6 4 · Not Applicable 2 · Other 0 | 72 |
| Application | DNS 10 · HTTP 0 · TLS 0 · Other / Not Detected 62 | 72 |

Example: DNS packet #11 is counted as **IPv4** in the network chart, **UDP** in the
transport chart and **DNS** in the application chart. Grey bars are the "catch-all"
categories (Other / Not Applicable).

**Top talkers:** the 5 IPs that sent / received the most packets.

- Top source: **192.168.1.10 with 37** packets. The laptop starts almost everything.
- Top destination: **192.168.1.10 with 27**, followed by `8.8.8.8` with 9 (4 pings + 5 DNS
  queries).
- Several websites have tied counts (4 sent, 6 received each). With ties, the order among
  them is not meaningful.

### 6.3 Packet Explorer page

**The packet table** shows one row per packet: number, timestamp, source/destination IP,
protocol, ports and length. The **Protocol** column shows the *most specific* protocol
known: DNS beats UDP, UDP beats IPv4. Ports are blank for ARP and ICMP because those
protocols have no ports.

**Filters**: try these on the sample:

| Filter | Result | Packets |
|---|---|---|
| Protocol = DNS | 10 packets | 11, 12, 23, 24, 35, 36, 47, 48, 61, 62 |
| Protocol = TCP | 42 packets | 13–22, 25–34, 37–46, 49–60 |
| Protocol = IPv6 | 4 packets | 68–71 |
| Protocol = ARP **and** ICMP (both selected) | 13 packets | 1–10, 63, 64, 72 |
| Source IP contains `192.168.1.23` | 2 packets | 61, 63 (the phone) |
| Destination IP contains `8.8.8.8` | 9 packets | 3, 5, 7, 9, 11, 23, 35, 47, 61 |
| Protocol = TCP **and** destination contains `93.184.216.34` | 6 packets | 13, 15, 16, 19, 20, 22 |
| Source IP contains `192.168.1.` (partial) | 43 packets | everything sent from the local network |

Rules:
- Selecting **several protocols** = show packets matching **any** of them (OR).
- Protocol + IP filters together = packets must match **all** of them (AND).
- IP filters allow **partial text**, so `192.168.1.` matches the whole subnet.
- Filtering never changes the Overview statistics. Filters work on a copy.
- **HTTP** and **TLS** are also in the protocol list. They find 0 packets in the mixed
  sample and 3 and 8 packets in the web demo.

**Export CSV:** the button at the top right of the packet table downloads the packets
*currently shown* (after filters) as a `.csv` file. You can open it in Excel or load it in
Python. It contains every metadata column (32, listed in section 7.3), one row per packet,
but no payload bytes. Example: filter **DNS** on the sample and export → 10 rows.

**Packet details:** click a row (or type a packet number). The details are shown
**layer by layer**, in the same order as the TCP/IP model:

| Card | Shows |
|---|---|
| Frame | Packet number, timestamp, time since first packet, length |
| Data Link Layer | Source and destination MAC |
| Network Layer | IPv4/IPv6/ARP, source and destination IP (+ ARP operation) |
| Transport Layer | TCP/UDP/ICMP, ports (+ TCP flags, seq, ack and payload length, or ICMP type/code/message) |
| Application Layer | DNS (+ query/response, domain, record type), HTTP (+ request line and Host, or status), TLS (+ record types, version, SNI) or Other |

Four great packets to demonstrate:

| Packet | Why it's interesting |
|---|---|
| **#1** | ARP broadcast: destination MAC `ff:ff:ff:ff:ff:ff`, transport "Not Applicable" |
| **#12** | DNS response for example.com: shows UDP ports 53 → 62779 and DNS fields |
| **#13** | TCP SYN: flags `SYN`, sequence 5194038, ack 0 |
| **#72** | ICMP destination unreachable, correctly *not* counted as UDP |

And three in the web demo:

| Packet | Why it's interesting |
|---|---|
| **#8** | HTTP request: `GET /index.html`, Host `example.com`, payload 87 bytes |
| **#19** | TLS Client Hello: version TLS 1.3, server name `www.wikipedia.org` |
| **#20** | Three TLS records in one segment: Server Hello, Change Cipher Spec, Application Data |

### 6.4 Protocol Analysis page

**Layer tables:** the same counts as the Overview, with exact percentages
(e.g. TCP = 42 / 72 = **58.33%**) and a "Share" bar.

**TCP flag combinations:** ACK 16, PSH+ACK 8, FIN+ACK 8, SYN 5, SYN+ACK 4, RST+ACK 1.
You can read the whole story from this table: 5 connection attempts (SYN), 4 accepted
(SYN+ACK), 1 refused (RST), 4 closed properly (8 FIN = 2 per connection).

**Three-way handshakes:** NetScope finds the **4** completed handshakes. The RTT column
is the time from the SYN to the SYN-ACK, which is one round trip to the server:

| Client | Server | SYN | SYN-ACK | ACK | RTT (ms) |
|---|---|---|---|---|---|
| 192.168.1.10:56299 | 93.184.216.34:443 | 13 | 14 | 15 | 59.046 |
| 192.168.1.10:57866 | 208.80.154.224:443 | 25 | 26 | 27 | 75.277 |
| 192.168.1.10:55786 | 140.82.112.3:443 | 37 | 38 | 39 | 55.006 |
| 192.168.1.10:55248 | 151.101.0.223:443 | 49 | 50 | 51 | 37.132 |

The refused connection (59 → 60) is correctly **not** in this list.

**Retransmissions:** TCP segments sent again with a sequence number already used. The mixed
sample has **none**. The web demo has **2**:

| Packet | Connection | Seq | Payload | Original | Delay |
|---|---|---|---|---|---|
| 11 | 93.184.216.34:80 → 192.168.1.10:50100 | 1921578 | 99 B | 10 | 300 ms |
| 24 | 192.168.1.10:50200 → 208.80.154.224:443 | 4180257615 | 425 B | 22 | 313 ms |

**Round-trip time per connection:** one row per **direction** (sender → receiver) with the
number of segments sent, retransmissions and the min / average / max RTT (see 3.12 and 7.5).
Web demo results:

| Sender → Receiver | Segments | Retrans. | Samples | Min / Avg / Max (ms) |
|---|---|---|---|---|
| laptop:50100 → example.com:80 | 3 | 0 | 3 | 42 / 42 / 42 |
| example.com:80 → laptop:50100 | 3 | 1 | 2 | 1 / 1 / 1 |
| laptop:50200 → wikipedia.org:443 | 5 | 1 | 4 | 65 / 65 / 65 |
| wikipedia.org:443 → laptop:50200 | 6 | 0 | 6 | 1 / 6.8 / 22 |

The laptop → server rows give the real network RTT (42 ms and 65 ms, the same as the
handshakes). The server → laptop rows only show how fast the laptop replied. Each
retransmitted segment gives **no** sample (Karn's algorithm), which is why there are fewer
samples than segments.

In the mixed sample, the RTT values in both directions range from a few to about 80
milliseconds, because the generator puts a random gap of 2–80 ms before every packet.
They are not real network measurements.

**Web traffic:** two tables that are empty for the mixed sample:
- **HTTP requests:** packet, client, Host, request line and the server's reply, matched on
  the same connection. Web demo: `8 · 192.168.1.10 · example.com · GET /index.html · 200 OK`.
- **TLS server names:** SNI names from Client Hello messages. Web demo: `www.wikipedia.org`.

**Conversations:** like Wireshark's *Statistics → Conversations*, one row per **pair of IP
addresses**. Both directions are combined, and ARP is left out because it has no IP header.
Address A is the one that sent first. Columns: total packets and bytes, packets/bytes
A→B and B→A, start time, duration and the protocols seen. The mixed sample has **10**
conversations. The biggest is `192.168.1.10 ↔ 8.8.8.8` with 16 packets (8 each way: 4 pings
and 4 DNS lookups), followed by the four websites with 10 packets each (6 sent by the
laptop, 4 by the server).

**ICMP / ICMPv6 messages:** echo-request 5, echo-reply 5 (ICMP); Echo Request 2,
Echo Reply 2 (ICMPv6); dest-unreach 1.

**Top queried DNS domains:** example.com 2, wikipedia.org 1, github.com 1, python.org 1.
Only **queries** are counted (not responses), so each lookup counts once.

**How classification works** (expandable box): a short summary of the rules in section 7.4.

### 6.5 About page

A summary of the workflow, the networking concepts demonstrated, the technologies, and
the privacy rules.

---

## 7. How the code works

### 7.1 Folder structure

```
netscope/
├── app.py                        # The web app: pages, sidebar, what to show
├── netscope/
│   ├── packet_parser.py          # Reads the file, extracts one record per packet
│   ├── protocol_analyzer.py      # Decides IPv4/TCP/DNS/HTTP/TLS... for each packet
│   ├── traffic_statistics.py     # Counts, top IPs, handshakes, retransmissions, RTT,
│   │                             # conversations, traffic over time, ICMP, DNS, HTTP, TLS
│   ├── filters.py                # Protocol and IP filters, CSV export
│   └── ui.py                     # Look and feel: colours, cards, charts
├── tests/                        # Automated tests (pytest)
├── sample_data/sample_capture.pcap     # Mixed-protocol demo (72 packets)
├── sample_data/web_demo_capture.pcap   # Web demo: HTTP, TLS, retransmissions (32 packets)
├── tools/make_sample_capture.py        # Builds the mixed demo file
├── tools/make_web_demo_capture.py      # Builds the web demo file
├── assets/                       # Logo
└── .streamlit/config.toml        # Theme and upload limit
```

### 7.2 The data flow

```
 .pcap file
     |
     v
 packet_parser.detect_format()     check the magic number -> "pcap" / "pcapng" / error
     |
     v
 Scapy PcapReader                  reads packets one by one (streaming)
     |
     v
 packet_parser.extract_metadata()  one packet -> one dictionary (record)
     |      uses protocol_analyzer to classify each layer
     v
 pandas DataFrame                  72 rows x 32 columns = the "packet table"
     |
     +--> traffic_statistics  -> tiles, traffic over time, top talkers, flags, handshakes,
     |                           retransmissions, RTT, conversations, ICMP, DNS, HTTP, TLS
     +--> protocol_analyzer   -> per-layer distributions
     +--> filters             -> Packet Explorer table and CSV export
     |
     v
 app.py + ui.py                    draw everything in Streamlit
```

### 7.3 `packet_parser.py`: reading the file

**Step 1, check the file.** `detect_format()` reads the first 4 bytes:
- empty file → error "The uploaded file is empty"
- unknown bytes → error "This file is not a valid PCAP or PCAPNG capture"
- otherwise → `"pcap"` or `"pcapng"`

**Step 2, read every packet.** Scapy's `PcapReader` gives one decoded packet at a time
(it does not load the whole file into memory at once).

**Step 3, build one record per packet.** `extract_metadata()` creates a dictionary with
these columns (the "packet metadata model"):

| Group | Columns |
|---|---|
| Identity | `packet_no`, `timestamp`, `time`, `relative_time`, `length` |
| Link layer | `src_mac`, `dst_mac` |
| Network layer | `src_ip`, `dst_ip`, `network_protocol`, `arp_operation` |
| Transport layer | `transport_protocol`, `src_port`, `dst_port`, `tcp_flags`, `tcp_seq`, `tcp_ack`, `tcp_payload_len`, `icmp_type`, `icmp_code`, `icmp_info` |
| Application layer | `application_protocol`, `dns_query`, `dns_query_type`, `dns_direction`, `http_info`, `http_host`, `tls_message`, `tls_version`, `tls_sni` |

`tcp_payload_len` is the number of data bytes in the TCP segment, with Ethernet padding
removed. The retransmission and RTT analysis need it. `http_info` holds either the request
line without the version (`GET /index.html`) or the status (`200 OK`).
| Summary | `protocol` (most specific name), `parse_error` |

For example, packet #13 becomes:
`src_ip=192.168.1.10, dst_ip=93.184.216.34, network=IPv4, transport=TCP, src_port=56299,
dst_port=443, tcp_flags="SYN", tcp_seq=5194038, length=54, application=Other`.

TCP flags are stored by Scapy as letters (`"SA"`), and NetScope converts them to readable
names (`"SYN, ACK"`).

**Step 4, make a DataFrame.** All records become a pandas table. Ports use a special
"nullable integer" type so ARP/ICMP rows show an empty port instead of `NaN`.

**Error handling (never crash):**

| Problem | What NetScope does |
|---|---|
| Empty file | Clear error message |
| Not a capture file (e.g. a renamed .txt) | Clear error message |
| Valid file with 0 packets | Clear error message |
| File cut off in the middle (truncated) | Analyzes the complete packets and shows a **warning** |
| One damaged packet | Keeps it, labels it "Other / Not Detected", records `parse_error`, shows a count in the sidebar |

To detect truncation, `is_truncated()` walks the file structure itself: it follows each
record's/block's length field and checks that the file ends exactly where the last packet
ends.

### 7.4 `protocol_analyzer.py`: classifying every packet

Each packet gets **three independent labels**, one per layer:

```
Network:      IPv4 | IPv6 | ARP | Other / Not Detected
Transport:    TCP | UDP | ICMP | ICMPv6 | Not Applicable (ARP) | Other / Not Detected
Application:  DNS | HTTP | TLS | Other / Not Detected
```

**Rule 1: trust the decoded headers, not port numbers.** A packet is labeled DNS only if
Scapy really decoded a DNS header from it, *and* it passes a sanity check: the DNS
"opcode" must be a valid value and the number of questions must match the header's
question count. Random bytes sent to port 53 are therefore **not** counted as DNS.

The same rule applies to HTTP and TLS, which NetScope parses itself from the TCP payload
(`tcp_payload()` returns the payload bytes without Ethernet padding):

- `parse_tls()`: the first byte must be a content type 20–23, the next two a version 3.0–3.4,
  and the length at most 18,432 bytes (the TLS maximum). It then walks through every record
  in the segment, collecting names like "Client Hello". For a Client or Server Hello,
  `_parse_hello()` steps over the fixed fields (version, 32-byte random, session ID, cipher
  suites, compression) to reach the **extensions**. From those it reads the SNI (extension 0)
  and the real version (extension 43, supported_versions). GREASE values (dummy versions
  like `0x3a3a` that browsers add on purpose) are ignored. Every length is checked, so a
  cut-off Hello never crashes.
- `parse_http()`: a regular expression checks the first line: a known method + path +
  `HTTP/1.0|1.1`, or `HTTP/1.x` + a status code 100–599. For a request, it reads headers
  only up to the blank line, looking for `Host:`.

TLS is checked before HTTP, and DNS before both. Example from the web demo, packet #19:
payload starts `16 03 01 …` → content type 22 (Handshake), version 3.1, then handshake
type 1 = **Client Hello** → SNI `www.wikipedia.org`, supported_versions lists TLS 1.3 →
label **TLS**.

**Rule 2: use the outermost layer.** The code walks the layers from the outside in
(`Ether → IP → ICMP → …`) and takes the **first** network layer and the **first** transport
layer it finds. This matters for packet **#72**: an ICMP error message contains a *copy*
of the failed packet's IP and UDP headers inside it. Taking the first match gives the
correct answer: **ICMP** from the router, not UDP.

**Rule 3: ARP has no transport layer.** So its transport label is "Not Applicable", which is
different from "Other" (which means "there is something, but we don't recognize it").

**Display name:** for the table, `display_protocol()` picks the most specific label:
application (if known) → transport → network.

**Distributions:** `network_distribution()` etc. count the labels and compute percentages.
They always include **every** category, even with 0 packets, so charts look the same for
every file.

### 7.5 `traffic_statistics.py`: the numbers

| Function | What it computes | Sample result |
|---|---|---|
| `total_packets` | rows in the table | 72 |
| `total_bytes` + `format_bytes` | sum of lengths, human readable | 10.12 KB |
| `unique_source_ips` / `unique_destination_ips` | distinct IPs | 10 / 11 |
| `dns_packet_count` | packets labeled DNS | 10 |
| `capture_duration` | last timestamp − first timestamp | 10.47 s |
| `top_ips` | 5 most frequent IPs | 192.168.1.10 first |
| `tcp_flag_counts` | TCP packets grouped by flags | ACK 16, … |
| `find_tcp_handshakes` | completed handshakes + handshake RTT | 4 |
| `tcp_retransmissions` | segments sent again with a used sequence number | 0 (web demo: 2) |
| `tcp_rtt` | RTT per direction (min / avg / max), retransmission count | 9 directions |
| `conversations` | packets and bytes per IP address pair, both directions | 10 pairs |
| `choose_interval` + `traffic_over_time` | packets and bytes per time interval | 21 intervals of 0.5 s |
| `icmp_type_counts` | ICMP/ICMPv6 grouped by message | echo-request 5, … |
| `top_dns_queries` | most queried domains (queries only) | example.com 2, … |
| `http_requests` | HTTP requests with Host and matching reply | none (web demo: 1) |
| `tls_server_names` | SNI names from Client Hellos | none (web demo: www.wikipedia.org) |

**The handshake detector (algorithm):** it goes through the TCP packets in order and
remembers them in two "waiting lists":

```
for each TCP packet:
    if flags = SYN only:
        remember it as "waiting for SYN-ACK"          (key = client ip:port, server ip:port)
    if flags = SYN + ACK:
        find the matching SYN going the other way
        check  ack == SYN.seq + 1                    -> remember as "waiting for ACK"
    if flags = ACK (no SYN):
        find the matching SYN-ACK
        check  ack == SYN-ACK.seq + 1                -> handshake COMPLETE, add to the list
```

Sequence numbers are compared **modulo 2³²**, because TCP sequence numbers wrap around
to 0 after 4,294,967,295.

Applied to the refused connection: SYN #59 is remembered, but #60 is RST (not SYN-ACK),
so it never completes. That's why the answer is 4, not 5. The handshake RTT is simply
`time(SYN-ACK) − time(SYN)`.

**Sequence space.** Both algorithms below need to know how much sequence space a segment
uses: `payload bytes + 1 if SYN + 1 if FIN`. A pure ACK uses 0, so it is never counted as a
retransmission and needs no acknowledgement.

**The retransmission detector:**

```
for each TCP packet that uses sequence space:
    key = (src ip, src port, dst ip, dst port, sequence number)
    if key was seen before:  -> RETRANSMISSION of that earlier packet (delay = time difference)
    else:                    remember key
```

Web demo: packet 22 has key (192.168.1.10, 50200, 208.80.154.224, 443, 4180257615). Packet
24 has the same key, so it is a retransmission of 22, sent 313 ms later.

**The RTT estimator:**

```
first pass:  count how many times each (direction, seq) was sent
second pass, for each TCP packet in order:
    1. if it has the ACK flag: every waiting segment from the OTHER direction whose
       end (seq + length) <= this ack number is now acknowledged
       -> RTT sample = this packet's time - that segment's time; stop waiting for it
    2. if it uses sequence space and was sent only ONCE (Karn's algorithm):
       start waiting for its ACK
report min / average / max of the samples, per direction
```

"≤" is calculated **modulo 2³²**, so it still works when sequence numbers wrap around to 0.
Web demo: packet 8 (seq 2395527357, 87 bytes) ends at 2395527444. Packet 9 carries
ack = 2395527444, so the sample is 0.372 − 0.330 = **42 ms**. Packets 10/11 have the same
sequence number, so neither gives a sample.

**Conversations:** packets are grouped by the *set* {source IP, destination IP}, so A→B and
B→A land in the same row. Only IPv4/IPv6 packets are included. The rows are sorted by
packet count.

**Traffic over time:** each packet's `relative_time` is divided by the interval and rounded
down to give its "bucket" number. The buckets are counted, and missing buckets are filled
with 0. `choose_interval()` picks the smallest "round" interval (0.001, 0.002, 0.005, …,
0.5, 1, 2, 5, 10, 15, 30, 60 s, …) that gives at most 40 buckets.

### 7.6 `filters.py`: filtering

- `filter_by_protocol()`: keeps rows matching **any** selected protocol (OR). Each filter name
  maps to a column, e.g. `"DNS"` → `application_protocol == "DNS"`, `"ARP"` →
  `network_protocol == "ARP"`.
- `filter_by_ip()`: keeps rows whose IP **contains** the typed text (partial match).
- `apply_filters()`: applies all three one after another (AND).
- Always returns a **new** table, never changes the original.
- `"HTTP"` and `"TLS"` map to `application_protocol == "HTTP"` / `"TLS"`.
- `to_csv()`: turns a (filtered) table into CSV bytes for the **Export CSV** button. It holds
  only the metadata columns, so payloads can never end up in the file.

### 7.7 `app.py` and `ui.py`: the interface

- `app.py` decides **what** to show. It creates the four pages with `st.navigation`,
  handles the upload and the sample toggle, and calls the analysis functions.
- `ui.py` decides **how** it looks. It holds the colour tokens, the stylesheet, and small
  building blocks: page header, KPI tiles, cards, key/value lists, the empty-state screen,
  the bar chart style and the traffic-over-time step chart (`time_chart`).
- **One colour per layer** everywhere: Network = blue, Transport = violet,
  Application = teal. Grey = "Other / Not Applicable".
- **Caching:** `analyze_capture()` is wrapped in `@st.cache_data`, so a file is parsed only
  once. Switching pages is instant.
- **Privacy:** the uploaded file is written to a temporary file only while Scapy reads it,
  then deleted immediately. Payload bytes are never stored or displayed. For HTTP and TLS
  only the header fields listed in 7.3 are kept.

### 7.8 Tests

`tests/` contains **62 automated tests**. They build small fake packets with Scapy (in
`conftest.py`) and check, for example, that:
- each protocol is classified correctly (TCP, UDP, ICMP, ARP, DNS, IPv6…);
- random bytes on port 53 are **not** DNS, and port 443 is **not** assumed to be TLS;
- payload bytes are never stored;
- every packet is counted exactly once per layer, and filters never change the original table;
- the three-way handshake detector finds real handshakes;
- empty, invalid, corrupted and truncated files give the right errors/warnings;
- PCAP and PCAPNG both work.

`test_future_scope.py` (23 tests) covers the newer features:
- HTTP requests and responses are detected, even on an unusual port, and the body is not
  stored. Text that only *looks* like HTTP (`GETTING…`, `HTTP/2.0`, status 999) is not;
- TLS 1.3 and TLS 1.2 Client Hellos (with/without SNI), a multi-record Server Hello, and
  Application Data labeled "(record layer)". 200 random payloads on port 443 are **not** TLS,
  and a Client Hello cut off at any byte does not crash;
- Ethernet padding is not counted as TCP payload;
- the HTTP/TLS filters and the CSV export (same columns, filtered rows, no payload);
- conversations combine both directions and skip ARP; traffic over time keeps empty intervals;
- retransmission and RTT with a sequence number that **wraps around 2³²**, Karn's rule, and
  a duplicate ACK that must not count as a retransmission;
- the whole web demo file end to end.

(The ICMP-error case from packet #72 is shown by the sample file but does not have its own
test yet. It would be a good one to add.)

---

## 8. Packet sizes: where every byte comes from

A good way to show you understand headers: explain each packet length in the sample.

| Packet (sample #) | Length | Breakdown |
|---|---|---|
| ARP (#1) | **42** | Ethernet 14 + ARP 28 |
| TCP control: SYN, ACK, FIN (#13) | **54** | Ethernet 14 + IPv4 20 + TCP 20 |
| TCP data, request (#16) | **274** | 54 headers + **220** bytes data |
| TCP data, response (#18) | **1254** | 54 headers + **1200** bytes data |
| ICMP ping, laptop (#3) | **58** | Ethernet 14 + IPv4 20 + ICMP 8 + 16 bytes ping data |
| ICMP ping, phone (#63) | **42** | Ethernet 14 + IPv4 20 + ICMP 8 (no data) |
| ICMPv6 ping (#68) | **62** | Ethernet 14 + IPv6 **40** + ICMPv6 8 |
| DNS query example.com (#11) | **71** | Ethernet 14 + IPv4 20 + UDP 8 + DNS 29 (12 header + 17 question) |
| Plain UDP (#65) | **202** | Ethernet 14 + IPv4 20 + UDP 8 + 160 bytes data |
| ICMP unreachable (#72) | **70** | Ethernet 14 + IPv4 20 + ICMP 8 + quoted IPv4 20 + quoted UDP 8 |
| Web demo: HTTP GET (#8) | **141** | 54 headers + **87** bytes HTTP request (request line + 3 headers + blank line) |
| Web demo: TLS Client Hello (#19) | **179** | 54 headers + 125 TLS = record header 5 + handshake header 4 + Hello body 116 |

Observations:
- A TCP packet with **no data** is still 54 bytes. That's the cost of headers.
- IPv6 headers are **twice** as big as IPv4 (40 vs 20 bytes).
- The UDP header (8) is much smaller than the TCP header (20).

---

## 9. Running, testing and rebuilding the sample

```powershell
# install
python -m pip install -r requirements.txt

# run the dashboard (opens http://localhost:8501)
python -m streamlit run app.py

# run the tests
python -m pytest -v

# rebuild the demo captures (same files every time)
python tools/make_sample_capture.py
python tools/make_web_demo_capture.py
```

**Demo script for a presentation (about 3 minutes):**
1. Open the app → show the welcome screen with the 4 capture steps.
2. Switch on **Use sample capture** → Overview: explain the 5 tiles and the 3 layer charts.
3. Packet Explorer → filter **DNS**, open packet **#11/#12** (query/response).
4. Clear the filter, open **#13, #14, #15** → explain the three-way handshake with the
   seq/ack numbers.
5. Open **#1** (ARP broadcast) and **#72** (ICMP unreachable).
6. Protocol Analysis → show the **4 handshakes** (with RTT), the **RST** in the flags table,
   the conversations and the DNS domains.
7. Switch the demo drop-down to **Web traffic** → Packet Explorer: open **#8** (HTTP GET) and
   **#19** (TLS Client Hello with SNI). Protocol Analysis: show the **2 retransmissions** and
   the RTT table (42 ms / 65 ms).
8. Optional: export the filtered packets with **Export CSV**, or upload your own Wireshark
   capture to show it works on real traffic.

---

## 10. Limitations and future improvements

**Current limitations**
- The application layer detects **DNS, HTTP/1.x and TLS**. Others (DHCP, QUIC, SMTP,
  HTTP/2 without TLS…) appear as "Other / Not Detected" (by design: no guessing from ports).
- HTTP and TLS are recognised **per packet**, without joining TCP segments back together
  (stream reassembly). A long HTTP body or a TLS record continued in the next segment is
  "Other / Not Detected" in those later segments.
- Encrypted contents cannot be read; only TLS handshake metadata is visible. With
  Encrypted Client Hello (ECH) the real SNI is hidden too.
- Offline only. It does not capture live traffic.
- Files are limited to 25 MB (changeable in `.streamlit/config.toml`).
- Only Ethernet-style captures are fully decoded; unusual link types may show as "Other".
- The retransmission detector does not tell apart the subtypes Wireshark shows (fast
  retransmission, spurious retransmission, out-of-order). RTT values depend on where the
  capture was taken (see 3.12).

**Already added (they were on the original future-scope list)**
- HTTP and TLS detection by header parsing, including the TLS SNI.
- Conversation table (packets and bytes per IP pair).
- Traffic-over-time chart.
- TCP retransmission and RTT analysis.
- CSV export of the filtered packets.

**Ideas for future versions**
- Optional live capture (needs Npcap and administrator rights on Windows).
- TCP stream reassembly, so HTTP/TLS split over several segments is recognised.
- Decode more application protocols (DHCP, QUIC, SMTP) and TLS 1.2 certificate names.
- Detect suspicious patterns (port scans = many SYNs with RST replies).

---

## 11. Quick viva answers

(For the full question bank, see `VIVA_PREPARATION.md`.)

**What does NetScope do?**
It reads a Wireshark capture file offline, decodes every packet with Scapy, classifies it
at the network, transport and application layers, computes statistics, and shows them in a
Streamlit dashboard.

**Why is ARP's transport layer "Not Applicable"?**
ARP works directly over Ethernet. It has no IP header and no TCP/UDP header at all.

**Why are the port-443 packets in the mixed sample "Other / Not Detected"?**
Their synthetic payload is random bytes, not a real TLS record, so the TLS header check
fails. NetScope only labels protocols whose header it actually decodes; it never guesses
from the port number. In the web demo, real TLS records on port 443 *are* labeled TLS.

**How do you detect HTTP and TLS?**
From the first bytes of the TCP payload. HTTP: a valid request line (`GET /index.html
HTTP/1.1`) or status line (`HTTP/1.1 200 OK`). TLS: a valid record header (content type
20–23, version 3.x, sensible length). Web demo: packets 8 (HTTP) and 19 (TLS).

**What is SNI and why can you see it in encrypted traffic?**
Server Name Indication: the website name the client puts in the TLS Client Hello, so the
server can choose the right certificate. It is sent before encryption starts, so it is
readable. Web demo packet 19: `www.wikipedia.org`.

**How do you detect a retransmission?**
The same sender sends a segment with a sequence number it has already used for data (or
SYN/FIN) on the same connection. Web demo: packet 24 repeats packet 22 (seq 4180257615,
425 bytes), 313 ms later.

**How do you measure RTT, and what is Karn's algorithm?**
RTT = time from a segment to the first ACK that covers it (ack ≥ seq + length). If a
segment was sent twice, we cannot know which copy the ACK answers, so it is not measured.
That rule is Karn's algorithm. Web demo: 42 ms to example.com, 65 ms to wikipedia.org.

**What is a conversation?**
All packets between one pair of IP addresses, in both directions, with packet and byte
counts per direction. Like Wireshark's *Statistics → Conversations*.

**How do you detect a three-way handshake?**
Match SYN → SYN-ACK (ack = seq+1) → ACK (ack = seq+1) using IP addresses, ports and
sequence/acknowledgement numbers. Sample: packets 13, 14, 15.

**Why 5 SYN but only 4 handshakes in the sample?**
Packet 59 tried port 8080 and was refused with RST (packet 60).

**Why does the ICMP unreachable packet not count as UDP?**
It contains a copy of the failed UDP header, but NetScope uses the outermost transport
layer, which is ICMP.

**Why do unique destinations (11) exceed unique sources (10)?**
`203.0.113.50` only received UDP packets and never sent anything back. UDP needs no reply.

**Why does each layer chart add up to 72?**
Every packet gets exactly one label per layer, so it is counted once in each chart.

**TCP vs UDP?**
TCP is connection-based, reliable and ordered (handshake, sequence numbers, ACKs). UDP is
connectionless, fast, with no guarantees. Sample: website traffic is TCP, DNS and the
"video call" stream are UDP.

**What are the sample files?**
Two synthetic captures built with Scapy, with no real traffic, so they are safe to share.
The mixed file (72 packets, `tools/make_sample_capture.py`) covers ARP, IPv4, IPv6, TCP,
UDP, ICMP, ICMPv6 and DNS. The web file (32 packets, `tools/make_web_demo_capture.py`)
covers HTTP, TLS with SNI, retransmissions and RTT.

**Is it safe/private?**
Yes. Everything is processed locally, the upload is deleted right after parsing, and
payloads are never shown.

---

## 12. Glossary

| Term | Simple meaning |
|---|---|
| **ACK** | TCP flag/number confirming received data ("next byte I expect") |
| **ARP** | Finds the MAC address for an IP address on the local network |
| **Broadcast** | A message to every device on the local network (`ff:ff:ff:ff:ff:ff`) |
| **Capture file** | A file containing recorded packets (.pcap / .pcapng) |
| **Client Hello** | First TLS handshake message, sent by the client. It lists versions, ciphers and the SNI |
| **Conversation** | All packets between one pair of IP addresses, in both directions |
| **CSV** | Comma-separated values: a plain-text table that Excel can open (used by Export CSV) |
| **DataFrame** | A table in pandas, which NetScope uses with one row per packet |
| **DNS** | Translates domain names into IP addresses |
| **Encapsulation** | Wrapping data in headers layer by layer |
| **Ephemeral port** | A temporary random port used by a client (49152–65535) |
| **Ethernet** | Link-layer protocol carrying packets on the local network |
| **FIN** | TCP flag: "I'm finished sending" |
| **GREASE** | Dummy values that browsers put in TLS lists on purpose, so servers learn to ignore unknown values |
| **Handshake** | SYN → SYN-ACK → ACK, the start of every TCP connection |
| **Header** | Control information at the start of a packet layer |
| **HTTP** | Web protocol: text requests (`GET /page`) and responses (`200 OK`) over TCP |
| **ICMP / ICMPv6** | Control/error messages for IPv4 / IPv6 (e.g. ping) |
| **IP address** | Address of a computer on a network (IPv4 or IPv6) |
| **Karn's algorithm** | Do not measure RTT for a segment that was sent more than once |
| **Link-local** | IPv6 address valid only on the local link (`fe80::`) |
| **MAC address** | Hardware address of a network card |
| **Magic number** | First bytes of a file that identify its format |
| **Npcap** | Windows driver that lets Wireshark capture packets |
| **Offline analysis** | Analyzing a saved file instead of live traffic |
| **Packet** | A small unit of data sent over a network |
| **Payload** | The actual data inside a packet (never shown by NetScope) |
| **Port** | Number identifying a program/service on a computer |
| **PSH** | TCP flag: deliver this data to the application now |
| **Retransmission** | A TCP segment sent again (same sequence number) because it was not acknowledged in time |
| **RST** | TCP flag: abort / refuse the connection |
| **RTT** | Round-trip time: from sending a segment until its acknowledgement arrives |
| **Scapy** | Python library for decoding and building packets |
| **Sequence number** | TCP's number for each byte sent, used for ordering |
| **SNI** | Server Name Indication: the website name in the TLS Client Hello, readable before encryption |
| **Streamlit** | Python library that turns scripts into web apps |
| **SYN** | TCP flag: "let's start a connection" |
| **TCP** | Reliable, connection-based transport protocol |
| **TLS** | Encryption used by HTTPS. Its records start with a 5-byte header (type, version, length) |
| **TLS record** | One unit of TLS data: 5-byte header + handshake message, alert or encrypted data |
| **TTL** | IP field limiting how many routers a packet can pass |
| **UDP** | Fast, connectionless transport protocol |
| **Wireshark** | The most popular program for capturing and inspecting packets |
