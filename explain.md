# NetScope Explained: The Complete Guide

This guide explains **everything** about NetScope in simple words: the networking theory,
the sample demo file, every screen of the app, and how the code works.

All examples use the built-in demo file **`sample_data/sample_capture.pcap`**, so you can
open the app, switch on **Use sample capture**, and see every number in this guide on your
own screen.

---

## Contents

1. [NetScope in one minute](#1-netscope-in-one-minute)
2. [Networking basics you need first](#2-networking-basics-you-need-first)
3. [The protocols, one by one (with real packets)](#3-the-protocols-one-by-one-with-real-packets)
4. [Capture files: Wireshark, PCAP and PCAPNG](#4-capture-files-wireshark-pcap-and-pcapng)
5. [The sample demo file](#5-the-sample-demo-file)
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
| **Altair** | Draws the bar charts |
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

### 3.10 HTTPS / TLS: why they appear as "Other / Not Detected"

The 40 packets to port 443 are web traffic (HTTPS). Their payload is encrypted with
**TLS**, so nobody in between can read it. NetScope's rule is: **only label a protocol if
its header was actually decoded**, never guess from the port number. TLS is not decoded,
so these packets are labeled **TCP** at the transport layer and **"Other / Not Detected"**
at the application layer. This is a deliberate, honest design choice (a packet on port 443
*could* be something else).

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

## 5. The sample demo file

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
| Malformed packets | 0 |

---

## 6. Walkthrough of the app using the sample

Start the app (`python -m streamlit run app.py`), open <http://localhost:8501>, and switch on
**Use sample capture** in the sidebar.

### 6.1 Sidebar

- **Navigation:** *Overview*, *Packet Explorer*, *Protocol Analysis* (the "Analyze"
  group) and *About*.
- **Capture file:** drag-and-drop box for your own `.pcap` / `.pcapng` (max 25 MB).
- **Use sample capture:** loads the demo file. An uploaded file always wins over the
  sample. The choice is kept in the URL (`?demo=1`) so a page refresh keeps it on.
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

**Protocol distribution:** three charts, one per layer. Each packet is counted **once in
each chart**, so every chart adds up to 72:

| Layer | Sample result | Adds up to |
|---|---|---|
| Network | IPv4 66 · IPv6 4 · ARP 2 · Other 0 | 72 |
| Transport | TCP 42 · UDP 13 · ICMP 11 · ICMPv6 4 · Not Applicable 2 · Other 0 | 72 |
| Application | DNS 10 · Other / Not Detected 62 | 72 |

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

**Packet details:** click a row (or type a packet number). The details are shown
**layer by layer**, in the same order as the TCP/IP model:

| Card | Shows |
|---|---|
| Frame | Packet number, timestamp, time since first packet, length |
| Data Link Layer | Source and destination MAC |
| Network Layer | IPv4/IPv6/ARP, source and destination IP (+ ARP operation) |
| Transport Layer | TCP/UDP/ICMP, ports (+ TCP flags, seq, ack, or ICMP type/code/message) |
| Application Layer | DNS (+ query/response, domain, record type) or Other |

Four great packets to demonstrate:

| Packet | Why it's interesting |
|---|---|
| **#1** | ARP broadcast: destination MAC `ff:ff:ff:ff:ff:ff`, transport "Not Applicable" |
| **#12** | DNS response for example.com: shows UDP ports 53 → 62779 and DNS fields |
| **#13** | TCP SYN: flags `SYN`, sequence 5194038, ack 0 |
| **#72** | ICMP destination unreachable, correctly *not* counted as UDP |

### 6.4 Protocol Analysis page

**Layer tables:** the same counts as the Overview, with exact percentages
(e.g. TCP = 42 / 72 = **58.33%**) and a "Share" bar.

**TCP flag combinations:** ACK 16, PSH+ACK 8, FIN+ACK 8, SYN 5, SYN+ACK 4, RST+ACK 1.
You can read the whole story from this table: 5 connection attempts (SYN), 4 accepted
(SYN+ACK), 1 refused (RST), 4 closed properly (8 FIN = 2 per connection).

**Three-way handshakes:** NetScope finds the **4** completed handshakes:

| Client | Server | SYN | SYN-ACK | ACK |
|---|---|---|---|---|
| 192.168.1.10:56299 | 93.184.216.34:443 | 13 | 14 | 15 |
| 192.168.1.10:57866 | 208.80.154.224:443 | 25 | 26 | 27 |
| 192.168.1.10:55786 | 140.82.112.3:443 | 37 | 38 | 39 |
| 192.168.1.10:55248 | 151.101.0.223:443 | 49 | 50 | 51 |

The refused connection (59 → 60) is correctly **not** in this list.

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
│   ├── protocol_analyzer.py      # Decides IPv4/TCP/DNS... for each packet
│   ├── traffic_statistics.py     # Counts, top IPs, handshakes, ICMP, DNS
│   ├── filters.py                # Protocol and IP filters
│   └── ui.py                     # Look and feel: colours, cards, charts
├── tests/                        # Automated tests (pytest)
├── sample_data/sample_capture.pcap
├── tools/make_sample_capture.py  # Builds the sample file
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
 pandas DataFrame                  72 rows x 26 columns = the "packet table"
     |
     +--> traffic_statistics  -> tiles, top talkers, flags, handshakes, ICMP, DNS
     +--> protocol_analyzer   -> per-layer distributions
     +--> filters             -> Packet Explorer table
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
| Transport layer | `transport_protocol`, `src_port`, `dst_port`, `tcp_flags`, `tcp_seq`, `tcp_ack`, `icmp_type`, `icmp_code`, `icmp_info` |
| Application layer | `application_protocol`, `dns_query`, `dns_query_type`, `dns_direction` |
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
Application:  DNS | Other / Not Detected
```

**Rule 1: trust the decoded headers, not port numbers.** A packet is labeled DNS only if
Scapy really decoded a DNS header from it, *and* it passes a sanity check: the DNS
"opcode" must be a valid value and the number of questions must match the header's
question count. Random bytes sent to port 53 are therefore **not** counted as DNS.

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
| `find_tcp_handshakes` | completed handshakes | 4 |
| `icmp_type_counts` | ICMP/ICMPv6 grouped by message | echo-request 5, … |
| `top_dns_queries` | most queried domains (queries only) | example.com 2, … |

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
so it never completes. That's why the answer is 4, not 5.

### 7.6 `filters.py`: filtering

- `filter_by_protocol()`: keeps rows matching **any** selected protocol (OR). Each filter name
  maps to a column, e.g. `"DNS"` → `application_protocol == "DNS"`, `"ARP"` →
  `network_protocol == "ARP"`.
- `filter_by_ip()`: keeps rows whose IP **contains** the typed text (partial match).
- `apply_filters()`: applies all three one after another (AND).
- Always returns a **new** table, never changes the original.

### 7.7 `app.py` and `ui.py`: the interface

- `app.py` decides **what** to show. It creates the four pages with `st.navigation`,
  handles the upload and the sample toggle, and calls the analysis functions.
- `ui.py` decides **how** it looks. It holds the colour tokens, the stylesheet, and small
  building blocks: page header, KPI tiles, cards, key/value lists, the empty-state screen
  and the bar chart style.
- **One colour per layer** everywhere: Network = blue, Transport = violet,
  Application = teal. Grey = "Other / Not Applicable".
- **Caching:** `analyze_capture()` is wrapped in `@st.cache_data`, so a file is parsed only
  once. Switching pages is instant.
- **Privacy:** the uploaded file is written to a temporary file only while Scapy reads it,
  then deleted immediately. Payload bytes are never stored or displayed.

### 7.8 Tests

`tests/` contains **39 automated tests**. They build small fake packets with Scapy (in
`conftest.py`) and check, for example, that:
- each protocol is classified correctly (TCP, UDP, ICMP, ARP, DNS, IPv6…);
- random bytes on port 53 are **not** DNS, and port 443 is **not** assumed to be TLS;
- payload bytes are never stored;
- every packet is counted exactly once per layer, and filters never change the original table;
- the three-way handshake detector finds real handshakes;
- empty, invalid, corrupted and truncated files give the right errors/warnings;
- PCAP and PCAPNG both work.

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

# rebuild the sample capture (same file every time)
python tools/make_sample_capture.py
```

**Demo script for a presentation (about 3 minutes):**
1. Open the app → show the welcome screen with the 4 capture steps.
2. Switch on **Use sample capture** → Overview: explain the 5 tiles and the 3 layer charts.
3. Packet Explorer → filter **DNS**, open packet **#11/#12** (query/response).
4. Clear the filter, open **#13, #14, #15** → explain the three-way handshake with the
   seq/ack numbers.
5. Open **#1** (ARP broadcast) and **#72** (ICMP unreachable).
6. Protocol Analysis → show the **4 handshakes**, the **RST** in the flags table and the
   DNS domains.
7. Optional: upload your own Wireshark capture to show it works on real traffic.

---

## 10. Limitations and future improvements

**Current limitations**
- Only **DNS** is detected at the application layer. HTTP, TLS, DHCP etc. appear as
  "Other / Not Detected" (by design: no guessing from ports).
- Offline only. It does not capture live traffic.
- Files are limited to 25 MB (changeable in `.streamlit/config.toml`).
- Only Ethernet-style captures are fully decoded; unusual link types may show as "Other".
- TCP analysis stops at the handshake/flags. It doesn't track retransmissions or
  measure speed.

**Ideas for future versions**
- Decode more application protocols (HTTP, TLS handshake, DHCP).
- Conversation view (group packets into flows).
- Timeline chart (packets per second).
- Detect suspicious patterns (port scans = many SYNs with RST replies).
- Export filtered packets to CSV.

---

## 11. Quick viva answers

(For the full question bank, see `VIVA_PREPARATION.md`.)

**What does NetScope do?**
It reads a Wireshark capture file offline, decodes every packet with Scapy, classifies it
at the network, transport and application layers, computes statistics, and shows them in a
Streamlit dashboard.

**Why is ARP's transport layer "Not Applicable"?**
ARP works directly over Ethernet. It has no IP header and no TCP/UDP header at all.

**Why are the HTTPS packets "Other / Not Detected"?**
Their payload is TLS-encrypted and not decoded. NetScope only labels protocols it actually
decodes; it never guesses from the port number.

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

**What is the sample file?**
72 synthetic packets built with Scapy (`tools/make_sample_capture.py`). No real traffic,
safe to share, and it covers every protocol NetScope understands.

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
| **DataFrame** | A table in pandas, which NetScope uses with one row per packet |
| **DNS** | Translates domain names into IP addresses |
| **Encapsulation** | Wrapping data in headers layer by layer |
| **Ephemeral port** | A temporary random port used by a client (49152–65535) |
| **Ethernet** | Link-layer protocol carrying packets on the local network |
| **FIN** | TCP flag: "I'm finished sending" |
| **Handshake** | SYN → SYN-ACK → ACK, the start of every TCP connection |
| **Header** | Control information at the start of a packet layer |
| **ICMP / ICMPv6** | Control/error messages for IPv4 / IPv6 (e.g. ping) |
| **IP address** | Address of a computer on a network (IPv4 or IPv6) |
| **Link-local** | IPv6 address valid only on the local link (`fe80::`) |
| **MAC address** | Hardware address of a network card |
| **Magic number** | First bytes of a file that identify its format |
| **Npcap** | Windows driver that lets Wireshark capture packets |
| **Offline analysis** | Analyzing a saved file instead of live traffic |
| **Packet** | A small unit of data sent over a network |
| **Payload** | The actual data inside a packet (never shown by NetScope) |
| **Port** | Number identifying a program/service on a computer |
| **PSH** | TCP flag: deliver this data to the application now |
| **RST** | TCP flag: abort / refuse the connection |
| **Scapy** | Python library for decoding and building packets |
| **Sequence number** | TCP's number for each byte sent, used for ordering |
| **Streamlit** | Python library that turns scripts into web apps |
| **SYN** | TCP flag: "let's start a connection" |
| **TCP** | Reliable, connection-based transport protocol |
| **TLS** | Encryption used by HTTPS |
| **TTL** | IP field limiting how many routers a packet can pass |
| **UDP** | Fast, connectionless transport protocol |
| **Wireshark** | The most popular program for capturing and inspecting packets |
