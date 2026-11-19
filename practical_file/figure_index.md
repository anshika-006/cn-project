# NetScope practical file: figure index

All screenshots are new captures from the running app (Streamlit 1.67.0 at http://127.0.0.1:8501, headless Chrome). Main pages are 1440 CSS px wide at 1.5× scale. Figures 12 and 13 are 1920 px wide at 1.25× scale. None of the four original images in `screenshots/` is used.

"Plan ID" is the number used in the original figure plan. "Report fig." is the figure number printed in the DOCX/PDF. The two are different because the architecture diagram is Figure 1 and the extra panels 02b and 05b get their own numbers.

| Plan ID | Report fig. | File | Steps | Expected evidence | Observed | Status |
|---|---|---|---|---|---|---|
| — | 1 | `00_architecture.svg` (+ `.png` preview) | Drawn by hand from the source code | Flow from capture → upload/sample → parser → classifier → DataFrame → filters/stats → 3 screens; processing on the Streamlit host | Inserted into the DOCX as a vector image | Done |
| 01 | 2 | `01_startup.png` | Fresh session, Overview, no capture | Upload box and sample toggle | Upload box (25 MB, PCAP/PCAPNG) and an empty-state card. Toggle is off | Done |
| 02 | 3 | `02_overview.png` | Overview with `?demo=1` | 72 pkts, 10.12 KB, 10 src, 11 dst, 10 DNS, ~10.47 s | Matches exactly. Active card reads "sample_capture.pcap · Demo · 72 packets · PCAP" | Done |
| 02b | 4 | `02b_top_talkers.png` | Same page, Top talkers section | 192.168.1.10: 37 sent, 27 received | Matches | Done |
| 03 | 5 | `03_packet_explorer_dns_filter.png` | Packet Explorer: DNS; source `192.168.1.10`; destination `8.8.8.8`; Enter after each | 4 of 72: #11, #23, #35, #47 | "Showing 4 of 72 packets", same rows | Done |
| 04 | 6 | `04_dns_packet_11.png` | Click row #11 in the filtered table | IPv4/UDP/DNS, 192.168.1.10:62779 → 8.8.8.8:53, A example.com | Matches. #12 response checked separately (`x_packet_12.png`, not in the report) | Done |
| 05 | 7 | `05_tcp_syn_packet_13.png` | TCP filter, click #13 | SYN 192.168.1.10:56299 → 93.184.216.34:443 | SYN, seq 5194038, ack 0; MACs, ports and flags visible | Done |
| 05b | 8 | `05b_handshake_triptych.png` | TCP filter, click #13, #14, #15 in turn; transport cards cropped and labelled | Handshake seq/ack values | 5194038/0 · 5541484/5194039 · 5194039/5541485 | Done (composite; labels added) |
| 06 | 9 | `06_arp_packet_1.png` | ARP filter, click #1 | Broadcast dst MAC, who-has 192.168.1.1, transport Not Applicable | Matches. 2 rows shown | Done |
| 07 | 10 | `07_ipv6_icmpv6_packet_68.png` | ICMPv6 filter, click #68 | fe80::10 → fe80::1, type 128 code 0, ports blank | Matches. 4 rows (#68–71) | Done |
| 08 | 11 | `08_layer_distributions.png` | Protocol Analysis, top tables | Each table sums to 72 | Counts match. Share is shown as bars only (numeric % come from the parser log) | Done |
| 09 | 12 | `09_tcp_flags_and_handshakes.png` | Protocol Analysis at 1920 px; panel (b) = handshake grid scrolled right | 4 handshakes, first 13/14/15; #59–60 only in the flag stats | Matches | Done (two-panel composite) |
| 10 | 13 | `10_icmp_and_dns_summary.png` | Protocol Analysis, Control & name resolution | ICMP 5/5/1, ICMPv6 2/2; example.com 2, three others 1 | Matches | Done |
| 11 | 14 | `11_pcapng_upload.png` | Fresh session, upload `NetScope_Demo_Data/sample_capture.pcapng` | PCAPNG read; metrics match the PCAP | PCAPNG badge, 72 packets, identical KPIs | Done |
| 12 | 15 | `12_invalid_file.png` | Upload the PCAPNG, then replace it with `invalid_demo.pcap` | Readable rejection | "This file is not a valid PCAP or PCAPNG capture. Save the capture from Wireshark using File > Save As (pcap or pcapng)." | Done |
| extra | 16 | `15_filter_dns_arp.png` | Filter DNS + ARP, no IP text | 12 rows | Showing 12 of 72 | Done |
| extra | 17 | `16_filter_no_match.png` | No protocol; source `198.51.100.254` | No-match state | Showing 0 of 72 + "No packets match the selected filters." | Done |
| extra | 18 | `14_no_packets.png` | Upload `no_packets.pcap` | "Contains no packets" | "The capture file is valid but contains no packets." | Done |
| extra | 19 | `13_truncated_warning.png` | Upload `truncated_demo.pcap` | Warning + readable results | Warning shown. 72 packets, final frame kept as partial (62 of 70 B), 10.11 KB (10,353 B) | Done |
| extra | 20 | `x_packet_61.png` | Packet-number field = 61 | AAAA query over IPv4/UDP | Matches | Done |
| extra | 21 | `x_packet_65.png` | Packet-number field = 65 | IPv4/UDP → 3478, app Other | Matches (60000 → 3478) | Done |
| extra | 22 | `x_packet_72.png` | Packet-number field = 72 | ICMP type 3 code 3 | Matches, dest-unreach | Done |
| — | — | `x_packet_3.png`, `x_packet_12.png` | Packet-number field = 3 / 12 | Echo request type 8; DNS response | Matches (cited in Table 8 / §6.4, not printed) | Done (file only) |
| — | — | Wireshark cross-check | Open the PCAP in Wireshark, filter `frame.number >= 13 && frame.number <= 15` | Same values as Table 5 | Wireshark is not installed on this machine | **Pending** |

## Rebuilding

From the project root:

```powershell
.\.venv\Scripts\python.exe practical_file\build_report.py     # writes the DOCX
.\.venv\Scripts\python.exe practical_file\finalize_word.py    # Word: vector diagram, TOC/LoF update, PDF export
```
