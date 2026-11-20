# TraceNet demo data

All frames in this kit are synthetic. The project generated them for offline analysis. Copy this folder beside the project's `app.py`. The three error-case files are ready to upload through the same sidebar control.

| File | How to use it | Expected evidence |
|---|---|---|
| `sample_capture.pcap` | Turn on the project's **Use sample capture** toggle or manually upload this identical copy. You can also open it directly in Wireshark. | 72 Ethernet frames, the full overview and packet examples below. |
| `sample_capture.pcapng` | Upload through the sidebar. | Format PCAPNG. Same frame bytes, sequence, timestamps, and displayed results as the PCAP. |
| `invalid_demo.pcap` | Upload through the sidebar. | Plain text with a .pcap extension; parser reports that the file is not a valid PCAP or PCAPNG capture. |
| `no_packets.pcap` | Upload through the sidebar. | A valid PCAP global header with zero frames; parser reports that the capture contains no packets. |
| `truncated_demo.pcap` | Upload through the sidebar. | A copy of the valid PCAP with eight bytes removed from the end. The app warns that the final packet may be missing or shortened, and displays the results it could read. |
| `packet_index.csv` | Open in a spreadsheet or use it as a report appendix. | All 72 rows of decoded packet metadata in capture order, including separate protocol labels, header fields and relative time in seconds. This file was generated with TraceNet's parser outside the dashboard. |

## Verified baseline

**72 packets · 10,361 captured frame bytes (10.12 KB displayed) · 10.47 seconds · 10 source IPs · 11 destination IPs**. The busiest source and destination are both `192.168.1.10`, with 37 sent and 27 received. The file itself takes more bytes than the summed frame lengths because PCAP adds file and per-record headers.

| TraceNet grouping | Packet counts |
|---|---|
| Network | IPv4 66, IPv6 4, ARP 2, Other / Not Detected 0 |
| Transport | TCP 42, UDP 13, ICMP 11, ICMPv6 4, Not Applicable 2, Other / Not Detected 0 |
| Application | DNS 10, Other / Not Detected 62 |
| TCP flags | ACK 16, PSH + ACK 8, FIN + ACK 8, SYN 5, SYN + ACK 4, RST + ACK 1 |
| TCP handshakes | 4 complete, at frames 13–15, 25–27, 37–39 and 49–51 |
| ICMP and ICMPv6 | IPv4 echo request 5, echo reply 5, destination unreachable 1. IPv6 echo request 2, echo reply 2. |
| DNS | 5 queries and 5 responses. Queries by domain: `example.com` 2, `wikipedia.org` 1, `github.com` 1, `python.org` 1. |

## Representative frames

| Frame(s) | What to point to |
|---|---|
| 1–2 | ARP request and reply. #1 has an Ethernet broadcast destination and asks for the MAC associated with `192.168.1.1`. #2 carries the reply. |
| 3–4 | IPv4 ICMP echo request (8, 0) and reply (0, 0) between `192.168.1.10` and `8.8.8.8`. |
| 11–12 | DNS query and response for `example.com` (A). #11 is IPv4/UDP/DNS and uses source port 62779 and destination port 53. |
| 13–15 | First complete TCP handshake between `192.168.1.10:56299` and `93.184.216.34:443`. See sequence and ACK values below. |
| 59–60 | Connection refused in the sample. #59 is SYN to `192.168.1.1:8080`; #60 is RST + ACK. |
| 61–62 | DNS AAAA query and response for `example.com`. This is a request for an IPv6 address, carried here by IPv4/UDP. |
| 65–67 | Plain IPv4/UDP from source port 60000 to destination port 3478. The application label is **Other / Not Detected**. |
| 68–69 | IPv6 echo request (128, 0) and reply (129, 0) between `fe80::10` and `fe80::1`. |
| 72 | IPv4 ICMP Destination Unreachable, type 3 code 3. The outer packet's ICMP header is the relevant classification despite the quoted UDP header. Use the complete capture for this example. |

| Frame | Direction | TCP flags | Sequence | ACK field |
|---|---|---|---:|---:|
| 13 | Client → Server | SYN | 5194038 | 0 (ACK flag clear) |
| 14 | Server → Client | SYN, ACK | 5541484 | 5194039 |
| 15 | Client → Server | ACK | 5194039 | 5541485 |

## Filter inputs for the report

| Protocol selection | Source IP contains | Destination IP contains | Expected rows |
|---|---|---|---|
| DNS | `192.168.1.10` | `8.8.8.8` | 4 (#11, #23, #35, #47) |
| DNS + ARP | blank | blank | 12 (10 DNS and 2 ARP) |
| ARP | blank | blank | 2 |
| ICMPv6 | blank | blank | 4 |
| No selection | `198.51.100.254` | blank | 0 |

For a quick viva, show the overview, the four-row DNS filter and #11, the #13–15 handshake table, then the invalid-capture message. The full figure plan is in `Antigravity_Prompt_NetScope.md`.
