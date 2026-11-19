"""Builds practical_file/NetScope_CN_Practical_File.docx.

Run from the project root with the project virtual environment:
    .venv\\Scripts\\python.exe practical_file\\build_report.py
Then run practical_file\\finalize_word.py to insert the vector diagram,
update the contents/figure list and export the PDF through Microsoft Word.
"""

import csv
import os
import re

from docx import Document
from docx.enum.section import WD_SECTION
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_BREAK
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Cm, Pt, RGBColor
from PIL import Image

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FIG = os.path.join(HERE, "figures")
OUT = os.path.join(HERE, "NetScope_CN_Practical_File.docx")
CSV = os.path.join(ROOT, "NetScope_Demo_Data", "packet_index.csv")

BODY_FONT = "Times New Roman"
CODE_FONT = "Consolas"
ACCENT = RGBColor(0x1F, 0x3A, 0x8A)

doc = Document()

# ---------------------------------------------------------------------------
# Page set-up and styles
# ---------------------------------------------------------------------------
sec = doc.sections[0]
sec.page_width, sec.page_height = Cm(21.0), Cm(29.7)
sec.left_margin = Cm(3.0)       # binding margin
sec.right_margin = Cm(2.0)
sec.top_margin = sec.bottom_margin = Cm(2.2)
TEXT_W = 21.0 - 3.0 - 2.0       # 16 cm


def set_font(style_or_run, name, size=None, bold=None, color=None):
    f = style_or_run.font
    f.name = name
    rpr = style_or_run.element.get_or_add_rPr()
    fonts = rpr.find(qn("w:rFonts"))
    if fonts is None:
        fonts = OxmlElement("w:rFonts")
        rpr.append(fonts)
    for a in ("w:ascii", "w:hAnsi", "w:cs", "w:eastAsia"):
        fonts.set(qn(a), name)
    for a in ("w:asciiTheme", "w:hAnsiTheme", "w:eastAsiaTheme", "w:cstheme"):
        if fonts.get(qn(a)) is not None:
            del fonts.attrib[qn(a)]
    if size:
        f.size = Pt(size)
    if bold is not None:
        f.bold = bold
    if color is not None:
        f.color.rgb = color


st = doc.styles
set_font(st["Normal"], BODY_FONT, 12)
pf = st["Normal"].paragraph_format
pf.space_after = Pt(6)
pf.line_spacing = 1.2

for name, size, before, after in (("Heading 1", 16, 18, 8), ("Heading 2", 13.5, 12, 4), ("Heading 3", 12, 8, 3)):
    s = st[name]
    set_font(s, BODY_FONT, size, True, ACCENT if name != "Heading 3" else RGBColor(0x1E, 0x29, 0x3B))
    s.font.italic = False
    s.paragraph_format.space_before = Pt(before)
    s.paragraph_format.space_after = Pt(after)
    s.paragraph_format.keep_with_next = True
st["Heading 1"].paragraph_format.page_break_before = True

cap = st["Caption"]
set_font(cap, BODY_FONT, 10.5, False, RGBColor(0x33, 0x41, 0x55))
cap.font.italic = True
cap.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.CENTER
cap.paragraph_format.space_before = Pt(3)
cap.paragraph_format.space_after = Pt(12)

code_style = st.add_style("CodeBlock", 1)
code_style.base_style = st["Normal"]
set_font(code_style, CODE_FONT, 9)
code_style.paragraph_format.space_after = Pt(0)
code_style.paragraph_format.line_spacing = 1.0

for lst in ("List Bullet", "List Number"):
    set_font(st[lst], BODY_FONT, 12)
    st[lst].paragraph_format.space_after = Pt(3)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
TOKEN = re.compile(r"(\*\*.+?\*\*|`.+?`)")


def add_runs(p, text, size=None):
    """Very small inline markup: **bold** and `code`."""
    for part in TOKEN.split(text):
        if not part:
            continue
        if part.startswith("**"):
            r = p.add_run(part[2:-2])
            r.bold = True
        elif part.startswith("`"):
            r = p.add_run(part[1:-1])
            set_font(r, CODE_FONT, (size or 12) - 1.5)
        else:
            r = p.add_run(part)
        if size and not part.startswith("`"):
            r.font.size = Pt(size)
    return p


def para(text, align=WD_ALIGN_PARAGRAPH.JUSTIFY, style=None, size=None):
    p = doc.add_paragraph(style=style)
    p.alignment = align
    return add_runs(p, text, size)


def bullets(items, numbered=False):
    for n, it in enumerate(items, 1):
        if numbered:  # explicit numbers so every list restarts at 1
            p = doc.add_paragraph()
            p.paragraph_format.left_indent = Cm(0.9)
            p.paragraph_format.first_line_indent = Cm(-0.6)
            p.paragraph_format.space_after = Pt(3)
            p.paragraph_format.tab_stops.add_tab_stop(Cm(0.9))
            add_runs(p, f"{n}.	" + it)
        else:
            add_runs(doc.add_paragraph(style="List Bullet"), it)


def h1(t):
    return doc.add_heading(t, level=1)


def h2(t):
    return doc.add_heading(t, level=2)


def h3(t):
    return doc.add_heading(t, level=3)


def shade(cell, hex_fill):
    tcpr = cell._tc.get_or_add_tcPr()
    shd = OxmlElement("w:shd")
    shd.set(qn("w:val"), "clear")
    shd.set(qn("w:color"), "auto")
    shd.set(qn("w:fill"), hex_fill)
    tcpr.append(shd)


def repeat_header(row):
    trpr = row._tr.get_or_add_trPr()
    el = OxmlElement("w:tblHeader")
    el.set(qn("w:val"), "true")
    trpr.append(el)


def no_split(row):
    trpr = row._tr.get_or_add_trPr()
    el = OxmlElement("w:cantSplit")
    el.set(qn("w:val"), "true")
    trpr.append(el)


def table(headers, rows, widths_cm, size=10, align_right=()):
    t = doc.add_table(rows=1, cols=len(headers))
    t.style = "Table Grid"
    t.alignment = WD_TABLE_ALIGNMENT.CENTER
    t.autofit = False
    for i, h in enumerate(headers):
        c = t.rows[0].cells[i]
        c.text = ""
        add_runs(c.paragraphs[0], f"**{h}**", size)
        shade(c, "DCE3F5")
    repeat_header(t.rows[0])
    for r in rows:
        cells = t.add_row().cells
        for i, v in enumerate(r):
            cells[i].text = ""
            p = cells[i].paragraphs[0]
            add_runs(p, str(v), size)
            if i in align_right:
                p.alignment = WD_ALIGN_PARAGRAPH.RIGHT
    for row in t.rows:
        no_split(row)
        for i, w in enumerate(widths_cm):
            row.cells[i].width = Cm(w)
            for p in row.cells[i].paragraphs:
                p.paragraph_format.space_after = Pt(1)
                p.paragraph_format.line_spacing = 1.0
    doc.add_paragraph().paragraph_format.space_after = Pt(2)
    return t


def table_caption(text):
    p = doc.add_paragraph(style="Caption")
    p.paragraph_format.space_before = Pt(8)
    p.paragraph_format.space_after = Pt(4)
    p.paragraph_format.keep_with_next = True
    add_runs(p, text, 10.5)


def figure(fname, caption, width_cm=TEXT_W, crop_h=None):
    path = os.path.join(FIG, fname)
    if crop_h:
        im = Image.open(path)
        if im.height > crop_h:
            tmp = os.path.join(os.environ.get("TEMP", HERE), "ns_" + fname)
            im.crop((0, 0, im.width, crop_h)).save(tmp)
            path = tmp
    im = Image.open(path)
    # Keep figures within ~19 cm height so a figure and caption fit one page.
    h_cm = width_cm * im.height / im.width
    if h_cm > 19.0:
        width_cm = width_cm * 19.0 / h_cm
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p.paragraph_format.keep_with_next = True
    p.paragraph_format.space_after = Pt(0)
    p.add_run().add_picture(path, width=Cm(width_cm))
    c = doc.add_paragraph(style="Caption")
    add_runs(c, caption, 10.5)


def code(lines):
    for i, ln in enumerate(lines):
        p = doc.add_paragraph(style="CodeBlock")
        p.paragraph_format.left_indent = Cm(0.5)
        if i < len(lines) - 1:
            p.paragraph_format.keep_with_next = True
        r = p.add_run(ln if ln else " ")
        set_font(r, CODE_FONT, 9)
    doc.add_paragraph().paragraph_format.space_after = Pt(0)


def field(p, instr, placeholder=""):
    r = p.add_run()
    b = OxmlElement("w:fldChar")
    b.set(qn("w:fldCharType"), "begin")
    b.set(qn("w:dirty"), "true")
    r._r.append(b)
    r2 = p.add_run()
    it = OxmlElement("w:instrText")
    it.set(qn("xml:space"), "preserve")
    it.text = f" {instr} "
    r2._r.append(it)
    r3 = p.add_run()
    s = OxmlElement("w:fldChar")
    s.set(qn("w:fldCharType"), "separate")
    r3._r.append(s)
    p.add_run(placeholder)
    r4 = p.add_run()
    e = OxmlElement("w:fldChar")
    e.set(qn("w:fldCharType"), "end")
    r4._r.append(e)


def page_break():
    doc.add_paragraph().add_run().add_break(WD_BREAK.PAGE)


# ---------------------------------------------------------------------------
# Cover page
# ---------------------------------------------------------------------------
for _ in range(2):
    doc.add_paragraph()
p = para("COMPUTER NETWORKS PRACTICAL FILE", WD_ALIGN_PARAGRAPH.CENTER)
p.runs[0].font.size = Pt(13)
p.runs[0].bold = True
p.runs[0].font.color.rgb = RGBColor(0x47, 0x55, 0x69)
doc.add_paragraph()
p = doc.add_paragraph()
p.alignment = WD_ALIGN_PARAGRAPH.CENTER
r = p.add_run("NetScope")
set_font(r, BODY_FONT, 34, True, ACCENT)
p = doc.add_paragraph()
p.alignment = WD_ALIGN_PARAGRAPH.CENTER
r = p.add_run("Offline Network Traffic Analysis and Packet Analyzer")
set_font(r, BODY_FONT, 17, True)
doc.add_paragraph()
para("A Python and Streamlit application that reads saved PCAP/PCAPNG capture files, classifies "
     "every packet at the network, transport and application layers, and presents filters, "
     "packet details and traffic statistics.", WD_ALIGN_PARAGRAPH.CENTER, size=12)
for _ in range(2):
    doc.add_paragraph()

cover = doc.add_table(rows=0, cols=2)
cover.style = "Table Grid"
cover.alignment = WD_TABLE_ALIGNMENT.CENTER
for k, v in [
    ("Submitted by", "[Student name(s)]"),
    ("Roll number(s)", "[Roll number(s)]"),
    ("Course and course code", "Computer Networks Lab · [Course code]"),
    ("Submitted to", "[Instructor name, designation]"),
    ("Department / Institution", "[Department], [Institution name]"),
    ("Programme and semester", "B.Tech · [Semester]"),
    ("Date of submission", "[DD Month YYYY]"),
]:
    c = cover.add_row().cells
    c[0].text, c[1].text = "", ""
    add_runs(c[0].paragraphs[0], f"**{k}**", 11.5)
    add_runs(c[1].paragraphs[0], v, 11.5)
    shade(c[0], "EEF2FF")
    c[0].width, c[1].width = Cm(5.5), Cm(9.5)

# ---------------------------------------------------------------------------
# Contents and list of figures
# ---------------------------------------------------------------------------
page_break()
p = doc.add_paragraph()
r = p.add_run("Contents")
set_font(r, BODY_FONT, 16, True, ACCENT)
field(doc.add_paragraph(), 'TOC \\o "1-2" \\h \\z \\u', "Right-click and choose Update Field to build the contents.")
p = doc.add_paragraph()
p.paragraph_format.space_before = Pt(18)
r = p.add_run("List of Figures and Tables")
set_font(r, BODY_FONT, 16, True, ACCENT)
field(doc.add_paragraph(), 'TOC \\h \\z \\t "Caption,1"', "Right-click and choose Update Field to build the list of figures.")

# ---------------------------------------------------------------------------
# 1. Abstract, aim and objectives
# ---------------------------------------------------------------------------
h1("1. Abstract, Aim and Objectives")
h2("1.1 Abstract")
para("NetScope is an offline packet analyzer developed as a Computer Networks mini-project. The input "
     "is a saved capture file in PCAP or PCAPNG format, such as a file saved from Wireshark. NetScope "
     "does not capture live traffic. It reads the saved file with the Scapy library, decodes each frame "
     "layer by layer, and stores one row of header metadata per packet in a Pandas DataFrame. Each "
     "packet is given three independent labels: a network-layer label (IPv4, IPv6 or ARP), a "
     "transport-layer label (TCP, UDP, ICMP or ICMPv6) and an application-layer label (DNS when a "
     "valid DNS header is decoded).")
para("The results are shown in a Streamlit web dashboard with three analysis screens. **Overview** "
     "gives summary counts, per-layer protocol charts and the busiest hosts. **Packet Explorer** "
     "filters the packet list and shows the decoded headers of a selected packet. **Protocol "
     "Analysis** gives per-layer tables, TCP flag statistics, completed three-way handshakes, ICMP "
     "message types and the most queried DNS domains. This report demonstrates these screens with "
     "a synthetic 72-frame demonstration capture and with three deliberately faulty files that test "
     "error handling.")
h2("1.2 Aim")
para("To design and demonstrate an offline tool that parses saved network capture files, classifies "
     "each packet according to the layered TCP/IP model, and presents filters and traffic statistics "
     "that make protocol behaviour (ARP, IP addressing, TCP handshake, UDP, ICMP and DNS) visible.")
h2("1.3 Objectives")
bullets([
    "**Capture-file parsing:** validate and read PCAP and PCAPNG files, and extract timestamps, MAC "
    "addresses, IP addresses, ports, lengths, TCP flags and sequence numbers, ICMP types and DNS questions.",
    "**Layered classification:** label every packet separately at the network, transport and "
    "application layers, without guessing application protocols from port numbers.",
    "**Packet filtering:** select packets by protocol and by source or destination IP text, and "
    "inspect any packet's decoded headers.",
    "**Traffic statistics:** compute packet and byte totals, unique hosts, top talkers, per-layer "
    "distributions, TCP flag combinations, completed three-way handshakes, ICMP message types and DNS query counts.",
    "**Robustness:** reject invalid or empty files with readable messages and warn when a file is truncated.",
])

# ---------------------------------------------------------------------------
# 2. Theory
# ---------------------------------------------------------------------------
h1("2. Theory")
para("A captured frame contains nested headers. The Ethernet header carries MAC addresses, the "
     "network header carries IP addresses (or an ARP message), the transport header carries ports or "
     "a control message, and the application data follows. NetScope reads these headers in order "
     "from the outermost layer inwards. Table 1 summarises the protocols that it recognises.")
table_caption("Table 1: Protocols and concepts demonstrated by NetScope")
table(["Concept", "NetScope grouping", "Key fields and behaviour", "Sample frames"], [
    ["Ethernet MAC addressing", "Data link (detail card)",
     "48-bit source and destination MAC. `ff:ff:ff:ff:ff:ff` is the broadcast address.", "#1 (broadcast)"],
    ["ARP request / reply", "Network layer: ARP",
     "Maps an IPv4 address to a MAC address. The request is broadcast; the reply is unicast. "
     "ARP has no IP header and no transport layer.", "#1, #2"],
    ["IPv4 / IPv6 addressing", "Network layer: IPv4, IPv6",
     "32-bit dotted-decimal and 128-bit hexadecimal addresses identify the end hosts.", "#11 (IPv4), #68 (IPv6)"],
    ["TCP ports and handshake", "Transport layer: TCP",
     "Connection-oriented. SYN, SYN+ACK, ACK set up a connection; each side's initial sequence "
     "number is acknowledged as ISN + 1.", "#13–#15"],
    ["UDP datagrams", "Transport layer: UDP",
     "Connectionless; only ports, length and checksum. Used here by DNS and by plain UDP to port 3478.", "#11, #65"],
    ["ICMP / ICMPv6", "Transport layer grouping: ICMP, ICMPv6",
     "Control and error messages carried directly in IP: echo request/reply (ping) and destination unreachable.", "#3, #4, #68, #72"],
    ["DNS query / response", "Application layer: DNS",
     "Resolves a name to an address record (A for IPv4, AAAA for IPv6). The response reverses the endpoints.", "#11, #12, #61"],
], [3.2, 3.4, 6.6, 2.8], size=9.5)

h2("2.1 How NetScope groups ARP and ICMP")
para("NetScope places **ARP** under its network-layer category because ARP is carried directly in "
     "an Ethernet frame, at the same position where an IP header would otherwise appear. ARP has no "
     "transport layer, so its transport label is **Not Applicable**.")
para("NetScope places **ICMP and ICMPv6** under its “Transport Layer” analysis grouping, "
     "because these messages occupy the position after the IP header where TCP or UDP would "
     "otherwise appear. In standard networking terminology, ICMP is not a transport protocol: it is "
     "the control-message protocol of IP and is part of the network layer. The grouping is a "
     "presentation choice that lets every packet receive exactly one label in each of the three tables.")

h2("2.2 Worked example: one frame, three layers (packet #11)")
para("Packet #11 of the demonstration capture is a single 71-byte Ethernet frame that carries three "
     "protocols at once:")
bullets([
    "**Network layer – IPv4:** source `192.168.1.10`, destination `8.8.8.8`.",
    "**Transport layer – UDP:** source port `62779` (a temporary client port), destination port `53`.",
    "**Application layer – DNS:** a query for the A (IPv4 address) record of `example.com`.",
])
para("Packet #12 is the matching response from `8.8.8.8:53` back to `192.168.1.10:62779`. Because "
     "every packet receives one label per layer, a DNS packet is counted once as IPv4 in the network "
     "table, once as UDP in the transport table and once as DNS in the application table (Figure 4, Figure 8).")
h2("2.3 An AAAA question can travel over IPv4")
para("The record type that a DNS query asks for does not depend on the IP version that carries the "
     "query. Packet #61 is sent from `192.168.1.23` to `8.8.8.8` over IPv4 and UDP, yet it asks for "
     "the **AAAA** record of `example.com`, that is, the IPv6 address of that name. Packet #62 is the "
     "response (Figure 20).")

# ---------------------------------------------------------------------------
# 3. System requirements and architecture
# ---------------------------------------------------------------------------
h1("3. System Requirements and Architecture")
h2("3.1 Software and hardware used")
table_caption("Table 2: Software environment used for this practical (versions as installed)")
table(["Component", "Version / detail", "Role"], [
    ["Operating system", "Windows 11", "Host machine for the Streamlit server and browser"],
    ["Python", "3.13.5 (isolated virtual environment `.venv`)", "Programming language"],
    ["Scapy", "2.8.0", "Reads PCAP/PCAPNG files and decodes each packet layer"],
    ["Pandas", "3.1.1", "Packet table (DataFrame), filters and statistics"],
    ["Streamlit", "1.67.0", "Web dashboard, file upload, navigation"],
    ["Altair", "6.3.0 (installed with Streamlit)", "Bar charts on the Overview page"],
    ["pytest", "9.2.0", "Automated tests"],
    ["Web browser", "Google Chrome", "Viewing the dashboard at http://127.0.0.1:8501"],
    ["Wireshark (optional)", "Not installed on this machine", "Capturing traffic and optional cross-checking"],
], [3.6, 5.6, 6.8], size=10)
para("Hardware requirements are modest: any computer that runs Python 3.10 or later and a modern "
     "browser is sufficient. NetScope only reads saved files, so it does not need Npcap or "
     "administrator rights. The upload limit is configured as **25 MB** in `.streamlit/config.toml`.")

h2("3.2 Architecture and data flow")
p = doc.add_paragraph()
p.alignment = WD_ALIGN_PARAGRAPH.CENTER
p.paragraph_format.keep_with_next = True
p.add_run("[[ARCH_SVG]]")
c = doc.add_paragraph(style="Caption")
add_runs(c, "Figure 1: NetScope workflow from a saved capture to the three analysis screens. All "
            "steps run on the machine that hosts the Streamlit server.", 10.5)
para("Figure 1 shows the processing pipeline. All processing runs on the machine that hosts the "
     "Streamlit server; in this practical that machine is the same laptop that runs the browser "
     "(`127.0.0.1`). If the server were deployed on another computer, the uploaded file would be "
     "processed on that computer instead.")
bullets([
    "**Input selection:** the sidebar accepts a `.pcap` or `.pcapng` upload, or the "
    "**Use sample capture** toggle loads the bundled `sample_data/sample_capture.pcap`. An upload "
    "always takes priority over the toggle.",
    "**Temporary file:** the uploaded bytes are written to a temporary file, because Scapy reads "
    "from a file path. The file is deleted in a `finally` block immediately after parsing, even if parsing fails.",
    "**Signature validation:** the first four bytes (the magic number) must match a PCAP header "
    "(four variants for byte order and timestamp resolution) or the PCAPNG Section Header Block. A "
    "file with a correct suffix but wrong content is rejected at this step.",
    "**Packet-by-packet decoding:** Scapy's `PcapReader` streams packets one at a time. For each "
    "packet the parser records one metadata row; a packet that cannot be fully decoded is still "
    "counted and is marked in a `parse_error` column.",
    "**Integrity check:** the parser walks the PCAP record headers (or PCAPNG block lengths) itself "
    "and warns if the file ends in the middle of a packet.",
    "**Metadata only:** the DataFrame stores timestamps, MAC and IP addresses, ports, length, TCP "
    "flags and sequence/acknowledgement numbers, ICMP type and code, ARP operation and the DNS "
    "question. Application payload bytes are never stored or displayed.",
    "**Caching:** the parsed DataFrame is cached in the server's memory (at most three captures) so "
    "that switching pages does not re-parse the file. The capture file itself is not kept on disk.",
])

# ---------------------------------------------------------------------------
# 4. Modules and method
# ---------------------------------------------------------------------------
h1("4. Module Descriptions and Method")
table_caption("Table 3: Source modules and their responsibilities")
table(["Module", "Responsibility"], [
    ["`app.py`", "Page set-up and navigation (Overview, Packet Explorer, Protocol Analysis, About); "
     "sidebar upload and sample toggle; suffix and size checks; temporary-file handling; error and warning messages; page layout."],
    ["`netscope/packet_parser.py`", "Magic-number validation, streaming read with Scapy, per-packet "
     "metadata extraction, truncation detection, conversion to a typed DataFrame."],
    ["`netscope/protocol_analyzer.py`", "Finds the outermost network layer and the first transport "
     "layer; assigns the network, transport and application labels; builds per-layer distribution tables."],
    ["`netscope/filters.py`", "Protocol and IP-address filters. Always returns a new DataFrame, so the "
     "overall statistics are never changed by filtering."],
    ["`netscope/traffic_statistics.py`", "Totals, unique IPs, top talkers, capture duration, TCP flag "
     "counts, three-way handshake detection, ICMP message counts and top DNS queries."],
    ["`netscope/ui.py`", "Visual design: colours, CSS, KPI tiles, cards, empty state and Altair bar charts."],
], [5.0, 11.0], size=10)

h2("4.1 Classification rules")
bullets([
    "**Network layer:** the outermost IPv4, IPv6 or ARP header. The outermost one is used because an "
    "ICMP error message contains a quoted copy of the original IP header.",
    "**Transport layer:** the first TCP, UDP, ICMP or ICMPv6 header found after the Ethernet header. "
    "For packet #72 (ICMP destination unreachable) the outer ICMP header is found before the quoted "
    "UDP header, so the packet is labelled ICMP.",
    "**Application layer:** DNS only when Scapy decodes a DNS header whose opcode is valid and whose "
    "question count matches the decoded questions. Traffic on port 53 that is not valid DNS is not "
    "counted as DNS, and TCP port 443 is not labelled TLS.",
])

h2("4.2 Filtering: OR within protocols, AND between filters")
para("Each protocol option maps to one layer column, for example DNS to the application label, ARP to "
     "the network label and TCP to the transport label. Options selected together in the multiselect "
     "are combined with **OR**. The protocol result is then combined with the source-IP and "
     "destination-IP text filters using **AND**:")
code([
    "def apply_filters(df, protocols=None, src_ip=None, dst_ip=None):",
    "    result = filter_by_protocol(df, protocols)     # any selected protocol (OR)",
    "    result = filter_by_ip(result, \"src_ip\", src_ip)  # AND source text",
    "    result = filter_by_ip(result, \"dst_ip\", dst_ip)  # AND destination text",
    "    return result",
])
para("The IP filters use literal, case-insensitive substring matching (`str.contains(..., regex=False)`). "
     "Typing `192.168.1.` therefore selects a whole subnet, but typing `192.168.1.1` also matches "
     "`192.168.1.10`. This explains the results of Figure 3 and Figure 15.")

h2("4.3 Three-way handshake detection")
para("`find_tcp_handshakes()` processes TCP packets in capture order and keys each connection by "
     "(client IP, client port, server IP, server port):")
bullets([
    "A packet with SYN and without ACK is stored as a pending SYN with its sequence number x.",
    "A packet with SYN and ACK is accepted only if it travels in the reverse direction of a pending SYN "
    "and its acknowledgement number equals x + 1 (modulo 2^32). Its own sequence number y is stored.",
    "A packet with ACK and without SYN completes the handshake only if it travels in the original "
    "direction and its acknowledgement number equals y + 1. One row is then reported with the three packet numbers.",
], numbered=True)
code([
    "if flags >= {\"SYN\"} and \"ACK\" not in flags:          # step 1",
    "    pending_syn[key] = {\"syn_no\": row.packet_no, \"seq\": row.tcp_seq}",
    "elif flags >= {\"SYN\", \"ACK\"}:                         # step 2",
    "    syn = pending_syn.get(reverse)",
    "    if syn and row.tcp_ack == (syn[\"seq\"] + 1) % mod: ...",
    "elif \"ACK\" in flags and \"SYN\" not in flags:            # step 3",
    "    if sa and row.tcp_ack == (sa[\"seq2\"] + 1) % mod: ...  # handshake found",
])
para("A refused connection (SYN answered by RST+ACK, packets #59–#60) never reaches step 2, so it "
     "appears in the flag statistics but not in the handshake table.")

# ---------------------------------------------------------------------------
# 5. Procedure
# ---------------------------------------------------------------------------
h1("5. Experimental Procedure")
h2("5.1 Input files")
para("The demonstration capture is **synthetic**: its 72 frames were generated with Scapy by the "
     "project's `tools/make_sample_capture.py` and contain no real user traffic. The public-looking "
     "addresses inside it (for example `8.8.8.8` and `93.184.216.34`) are only values written into "
     "offline frames; no network connection was made during this practical. All file names, host "
     "addresses, packet numbers and metrics in this report come from the actual input files listed in Table 4.")
table_caption("Table 4: Input files used")
table(["File", "Purpose"], [
    ["`sample_data/sample_capture.pcap`", "Loaded by the Use sample capture toggle (main demonstration)."],
    ["`NetScope_Demo_Data/sample_capture.pcap`", "Identical stand-alone copy for manual upload or Wireshark."],
    ["`NetScope_Demo_Data/sample_capture.pcapng`", "Same frames and timestamps in PCAPNG format."],
    ["`NetScope_Demo_Data/invalid_demo.pcap`", "Plain text with a .pcap suffix (invalid signature)."],
    ["`NetScope_Demo_Data/no_packets.pcap`", "Valid PCAP global header with zero frames."],
    ["`NetScope_Demo_Data/truncated_demo.pcap`", "Valid PCAP with the last 8 bytes removed."],
    ["`NetScope_Demo_Data/packet_index.csv`", "All 72 decoded rows, produced with NetScope's parser outside the UI (Appendix B)."],
], [7.2, 8.8], size=9.5)

h2("5.2 Steps")
bullets([
    "Open PowerShell in the project folder (the folder that contains `app.py`) and create an isolated "
    "environment: `python -m venv .venv`.",
    "Install the dependencies: `.\\.venv\\Scripts\\python.exe -m pip install -r requirements.txt`.",
    "Run the automated tests: `.\\.venv\\Scripts\\python.exe -m pytest -q`.",
    "Start the server: `.\\.venv\\Scripts\\python.exe -m streamlit run app.py --server.address 127.0.0.1 --server.port 8501`, "
    "then open `http://127.0.0.1:8501` in the browser.",
    "With no file loaded, observe the empty Overview page (Figure 2).",
    "Switch on **Use sample capture** in the sidebar (or open `http://127.0.0.1:8501/?demo=1`) and read the Overview (Figures 3 and 4).",
    "Open **Packet Explorer**. Select protocol **DNS**, type `192.168.1.10` in Source IP contains and "
    "`8.8.8.8` in Destination IP contains, pressing Enter after each. Click packet #11 (Figures 5 and 6).",
    "Clear the filters, select **TCP** and click packets #13, #14 and #15 (Figures 7 and 8). Repeat "
    "with **ARP** (packet #1, Figure 9) and **ICMPv6** (packet #68, Figure 10).",
    "Open **Protocol Analysis** and read the per-layer tables, TCP analysis and the ICMP/DNS tables (Figures 11–13).",
    "Return to Overview and upload `sample_capture.pcapng` (Figure 14), then replace it with "
    "`invalid_demo.pcap` (Figure 15), `no_packets.pcap` and `truncated_demo.pcap` (Figures 16 and 17).",
    "Stop the server with Ctrl + C.",
], numbered=True)

# ---------------------------------------------------------------------------
# 6. Results
# ---------------------------------------------------------------------------
h1("6. Results and Screenshots")
para("All screenshots were taken from the running application at a browser width of 1440 CSS pixels "
     "(1920 pixels for Figures 12 and 13). Timestamps in the screenshots are shown in the local time "
     "zone of the server machine.")

h2("6.1 Start-up screen")
figure("01_startup.png", "Figure 2: Overview with no capture loaded; the sidebar shows the capture-file "
       "upload box (PCAP, PCAPNG, 25 MB) and the Use sample capture option.")

h2("6.2 Overview of the demonstration capture")
figure("02_overview.png", "Figure 3: Overview with the sample capture: 72 packets, 10.12 KB of frame data "
       "(10,361 bytes), 10 source IPs, 11 destination IPs, 10 DNS packets over a 10.47 s span, with the three per-layer charts.")
figure("02b_top_talkers.png", "Figure 4: Top talkers: 192.168.1.10 is both the busiest source (37 packets "
       "sent) and the busiest destination (27 packets received).", width_cm=15)
para("The captured-data value is the sum of the frame lengths (10,361 bytes = 10.12 KB). The file on "
     "disk is larger (11,537 bytes) because PCAP adds a 24-byte global header and a 16-byte record "
     "header before each frame. The client `192.168.1.10` dominates both charts because it starts most "
     "of the conversations in the sample.")

h2("6.3 Packet Explorer: combined DNS filter")
figure("03_packet_explorer_dns_filter.png", "Figure 5: Packet Explorer with protocol DNS, source text "
       "192.168.1.10 and destination text 8.8.8.8: 4 of 72 packets match (#11, #23, #35 and #47).")
para("The protocol filter reads the application label, while the two address fields are literal "
     "substring filters. The three conditions are combined with AND, so only DNS queries from the "
     "client to the resolver remain. The responses (#12, #24, #36, #48) are excluded because their "
     "source is `8.8.8.8`. The fifth query, #61, is excluded because it comes from `192.168.1.23`.")

h2("6.4 DNS query: packet #11")
figure("04_dns_packet_11.png", "Figure 6: Packet #11 selected from the filtered table: IPv4 "
       "192.168.1.10 → 8.8.8.8, UDP 62779 → 53, DNS query for the A record of example.com.",
       width_cm=14)
para("This one frame carries IPv4, UDP and DNS labels, as explained in Section 2.2. The response "
     "#12 (verified in the application with the packet-number field) has source `8.8.8.8:53`, "
     "destination `192.168.1.10:62779`, DNS message **Response** and the same question.")

h2("6.5 TCP three-way handshake: packets #13 to #15")
figure("05_tcp_syn_packet_13.png", "Figure 7: Packet #13 with the TCP filter: SYN from "
       "192.168.1.10:56299 to 93.184.216.34:443, sequence number 5194038, acknowledgement field 0.",
       width_cm=13.5)
figure("05b_handshake_triptych.png", "Figure 8: Transport-layer cards of packets #13, #14 and #15 "
       "selected one after another (labels added above each card).")
table_caption("Table 5: First three-way handshake (values read from Figure 8)")
table(["Frame", "Direction", "TCP flags", "Sequence", "Acknowledgement"], [
    ["13", "Client → Server (192.168.1.10:56299 → 93.184.216.34:443)", "SYN", "5194038", "0 (ACK flag clear)"],
    ["14", "Server → Client", "SYN, ACK", "5541484", "5194039 = 5194038 + 1"],
    ["15", "Client → Server", "ACK", "5194039", "5541485 = 5541484 + 1"],
], [1.4, 6.6, 2.0, 2.2, 3.8], size=9.5)
para("Each side acknowledges the other side's initial sequence number plus one, which is exactly the "
     "condition used by the handshake detector in Section 4.3. Destination port 443 is commonly used "
     "for HTTPS, but NetScope does not label these packets TLS: a port number alone does not prove "
     "which application protocol is in use, so the application label is Other / Not Detected.")

h2("6.6 ARP: packet #1")
figure("06_arp_packet_1.png", "Figure 9: ARP filter: two results. Packet #1 is an ARP request from "
       "192.168.1.10 for 192.168.1.1, sent to the Ethernet broadcast address ff:ff:ff:ff:ff:ff; the transport layer is Not Applicable.",
       width_cm=14)
para("Packet #2 is the unicast reply (operation **Reply (is-at)**) from `192.168.1.1` to "
     "`192.168.1.10`. The ports are blank because ARP has no transport layer.")

h2("6.7 IPv6 and ICMPv6: packet #68")
figure("07_ipv6_icmpv6_packet_68.png", "Figure 10: ICMPv6 filter: packet #68 is an IPv6 echo request "
       "(type 128, code 0) from fe80::10 to fe80::1; the port fields are blank.", width_cm=13.5)
para("Packet #69 is the echo reply (type 129, code 0) in the opposite direction. Packets #70 and #71 "
     "repeat the request/reply pair. ICMP messages have no port numbers, so the port rows show a dash.")

h2("6.8 Protocol Analysis: per-layer distributions")
figure("08_layer_distributions.png", "Figure 11: Protocol Analysis: the network, transport and "
       "application tables each sum to 72 packets; the Share column shows each count as a bar.")
table_caption("Table 6: Protocol counts (from Figure 11) and percentages computed by protocol_analyzer.py")
table(["Layer", "Protocol counts (percentage of 72)", "Sum"], [
    ["Network", "IPv4 66 (91.67 %), IPv6 4 (5.56 %), ARP 2 (2.78 %), Other 0", "72"],
    ["Transport", "TCP 42 (58.33 %), UDP 13 (18.06 %), ICMP 11 (15.28 %), ICMPv6 4 (5.56 %), Not Applicable 2 (2.78 %), Other 0", "72"],
    ["Application", "DNS 10 (13.89 %), Other / Not Detected 62 (86.11 %)", "72"],
    ["TCP flags", "ACK 16, PSH+ACK 8, FIN+ACK 8, SYN 5, SYN+ACK 4, RST+ACK 1", "42"],
], [2.6, 11.8, 1.6], size=9.5, align_right=(2,))
para("Each table uses its own layer's packets as the denominator, so the percentages in each table "
     "add up to 100 % (small differences can appear after rounding to two decimals). The dashboard shows "
     "these shares as bars; the numeric percentages above are the values returned by "
     "`protocol_analyzer.py` for the same capture.")
para("**Why DNS packets also appear under UDP and IPv4.** The 10 DNS packets are 5 queries (#11, #23, "
     "#35, #47, #61) and 5 responses (#12, #24, #36, #48, #62). Every one of them is an IPv4 packet "
     "carrying a UDP datagram, so each is counted in the IPv4 row, in the UDP row and in the DNS row. "
     "The UDP total of 13 is these 10 DNS packets plus the 3 plain UDP packets #65–#67 to port 3478.")

h2("6.9 TCP analysis")
figure("09_tcp_flags_and_handshakes.png", "Figure 12: TCP flag combinations and the four completed "
       "three-way handshakes; panel (b) is the same table scrolled right so the SYN, SYN-ACK and ACK packet columns are readable.")
para("Four handshakes are found: 13–14–15, 25–26–27, 37–38–39 and 49–50–51, all from "
     "`192.168.1.10` to port 443 on four different servers. The flag table counts **5 SYN** packets "
     "but only **4 SYN+ACK** packets. The fifth SYN is #59 to `192.168.1.1:8080`, which was answered "
     "by #60 with **RST+ACK** (connection refused); it therefore appears in the flag statistics but has "
     "no row in the handshake table. The 8 FIN+ACK packets are the orderly closes of the four connections (two per connection).")

h2("6.10 ICMP and DNS summary")
figure("10_icmp_and_dns_summary.png", "Figure 13: ICMP/ICMPv6 message types (5 echo requests, 5 echo "
       "replies, 1 destination unreachable, 2 IPv6 echo requests and 2 IPv6 echo replies) and DNS query counts by domain.")
para("The domain table counts DNS **queries** only, not responses: `example.com` appears twice (the A "
     "query #11 and the AAAA query #61) and `wikipedia.org`, `github.com` and `python.org` once each, "
     "giving the 5 queries. The single destination-unreachable message is packet #72 (type 3, code 3, "
     "port unreachable).")

h2("6.11 PCAPNG upload")
figure("11_pcapng_upload.png", "Figure 14: Manual upload of sample_capture.pcapng: the active-capture "
       "card shows the PCAPNG format and 72 packets, and the metrics match the PCAP version.")
para("The PCAPNG file contains the same frame bytes and timestamps as the PCAP file. A comparison "
     "using the parser confirmed that all 72 timestamps and frame lengths are identical, so every metric matches Figure 3.")

h2("6.12 Invalid capture file")
figure("12_invalid_file.png", "Figure 15: invalid_demo.pcap has a supported suffix but an invalid file "
       "signature and is rejected with a readable message; no analysis is shown.")

# ---------------------------------------------------------------------------
# 7. Testing
# ---------------------------------------------------------------------------
h1("7. Testing and Validation")
h2("7.1 Functional test cases")
para("Each observed result below was checked in the running application and, where a number is "
     "given, also against the parser output for the same file.")
table_caption("Table 7: Functional test cases")
table(["#", "Case", "Input / action", "Expected output", "Observed output", "Fig."], [
    ["1", "PCAP (sample)", "Use sample capture", "72 packets, 10.12 KB, 10/11 IPs, 10 DNS", "As expected; format PCAP", "3"],
    ["2", "PCAPNG upload", "Upload sample_capture.pcapng", "Accepted; same metrics as PCAP", "PCAPNG badge, 72 packets, identical metrics", "14"],
    ["3", "Combined DNS filter", "DNS + src 192.168.1.10 + dst 8.8.8.8", "4 rows: #11, #23, #35, #47", "Showing 4 of 72; same four rows", "5"],
    ["4", "OR within protocols", "DNS + ARP, no IP text", "12 rows (10 DNS + 2 ARP)", "Showing 12 of 72", "16"],
    ["5", "No match", "No protocol, src 198.51.100.254", "Empty-result message", "Showing 0 of 72 and “No packets match the selected filters”", "17"],
    ["6", "Invalid signature", "Upload invalid_demo.pcap", "Rejected with readable message", "“This file is not a valid PCAP or PCAPNG capture…”", "15"],
    ["7", "Valid file, no frames", "Upload no_packets.pcap", "“Contains no packets” message", "“The capture file is valid but contains no packets.”", "18"],
    ["8", "Truncated file", "Upload truncated_demo.pcap", "Warning plus the readable results", "Warning shown; 72 packets analysed; final frame #72 kept as partial (62 of 70 bytes); 10,353 bytes (10.11 KB)", "19"],
    ["9", "ARP filter", "ARP only", "2 rows", "#1 request, #2 reply", "9"],
    ["10", "ICMPv6 filter", "ICMPv6 only", "4 rows", "#68–#71", "10"],
    ["11", "Handshakes", "Protocol Analysis", "4 complete; #59–60 excluded", "4 rows; no row for #59", "12"],
], [0.8, 2.4, 3.1, 3.1, 5.4, 1.2], size=8.5)
para("Figure numbers 16 to 22 refer to the supplementary evidence in Appendix D.", size=11)

h2("7.2 Verification of additional packets")
table_caption("Table 8: Additional packet checks (packet-number field in Packet Explorer)")
table(["Packet(s)", "Expected", "Observed in the application"], [
    ["#65 (regular UDP)", "IPv4/UDP, destination port 3478, application Other / Not Detected",
     "IPv4, UDP 60000 → 3478, 192.168.1.10 → 203.0.113.50, application Other / Not Detected (Figure 21)"],
    ["#3 / #4 (IPv4 ping)", "ICMP echo request type 8 and echo reply type 0",
     "#3 type 8 code 0 echo-request, 192.168.1.10 → 8.8.8.8; #4 type 0 code 0 echo-reply"],
    ["#72 (ICMP error)", "Type 3, code 3; transport label from the outer ICMP header",
     "ICMP, type 3, code 3, dest-unreach, 192.168.1.1 → 192.168.1.10, no ports (Figure 22)"],
    ["#61 (AAAA query)", "DNS AAAA query carried over IPv4/UDP",
     "IPv4, UDP 50123 → 53, DNS Query, example.com, type AAAA (Figure 20)"],
], [3.0, 5.5, 7.5], size=9.5)
para("Note: the “Or enter a packet number to inspect” field opens any packet in the whole "
     "capture, including packets outside the current filter. Filter demonstrations in this report "
     "therefore use a visible row selected from the filtered table.", size=11)

h2("7.3 Automated tests")
para("Command (run in the project folder with the virtual environment):")
code([".\\.venv\\Scripts\\python.exe -m pytest -q"])
para("Result: **39 passed in 7.72 s** (first run; a later re-run gave 39 passed in 0.94 s). The tests "
     "in `tests/test_packet_parser.py` and `tests/test_protocol_analyzer.py` use synthetic packets and "
     "cover IPv4/TCP, UDP, ICMP echo, ARP, DNS, port 53 without DNS, IPv6, unsupported layers, a "
     "truncated TCP header, payload not stored, PCAP and PCAPNG reading, empty, header-only, invalid, "
     "corrupted and truncated files, layer classification, port 443 not assumed TLS, distributions, "
     "statistics, filters not modifying the original data, and handshake detection.")

h2("7.4 Optional Wireshark cross-check")
para("Wireshark is not installed on the machine used for this practical, so this cross-check is "
     "**pending**. To perform it: open `NetScope_Demo_Data/sample_capture.pcap` with File → Open, "
     "apply the display filter `frame.number >= 13 && frame.number <= 15` and compare with Table 5, "
     "then apply `frame.number == 11` and compare with Figure 6. Wireshark shows *relative* TCP "
     "sequence numbers by default (0 and 1); either label them as relative or disable "
     "Edit → Preferences → Protocols → TCP → “Relative sequence numbers” "
     "before comparing with the absolute values shown by NetScope.")

# ---------------------------------------------------------------------------
# 8. Limitations, future scope, conclusion
# ---------------------------------------------------------------------------
h1("8. Limitations, Future Scope and Conclusion")
h2("8.1 Implemented scope and limitations")
bullets([
    "Analysis is **offline only**: NetScope reads saved PCAP/PCAPNG files and does not capture live traffic.",
    "The configured upload limit is **25 MB**; Scapy is written in Python, so very large files are slow.",
    "The dashboard shows **header metadata only**; payload bytes are not stored, displayed or interpreted.",
    "Application-layer classification is limited to **DNS**. HTTP, TLS and other protocols are shown "
    "as Other / Not Detected rather than guessed from port numbers (a TCP destination port of 443 alone does not establish TLS).",
    "Statistics are **layer-specific**: each packet is counted once in each of the three layer tables.",
    "IP fragments are not reassembled, and tunnelled traffic is classified by its outermost header.",
    "Timestamps are displayed in the local time zone of the server machine.",
])
h2("8.2 Future scope")
bullets([
    "Optional live capture with the required permissions.",
    "HTTP and TLS identification by parsing real headers (for example the TLS Client Hello), not by port number.",
    "Limited payload interpretation for selected protocols.",
    "Export of the filtered packet table to CSV.",
    "Conversation (flow) tables, a traffic-over-time chart, and TCP retransmission and round-trip-time analysis.",
])
h2("8.3 Conclusion")
para("NetScope successfully parsed both the PCAP and the PCAPNG versions of the 72-frame "
     "demonstration capture and produced identical results for both. Every packet received one label "
     "per layer, and each layer table added up to 72. The combined filter isolated exactly the four "
     "client-to-resolver DNS queries; the packet details showed IPv4, UDP and DNS together in frame #11, "
     "ARP broadcast resolution in frames #1–#2, and ICMPv6 echo messages in frames #68–#69. The handshake "
     "detector found the four complete SYN, SYN+ACK, ACK exchanges by matching endpoints, ports and "
     "acknowledgement numbers, and correctly excluded the refused connection. Invalid, empty and truncated "
     "files were handled with clear messages instead of crashes, and all 39 automated tests passed. "
     "The practical therefore demonstrates capture-file parsing, layered protocol classification, "
     "packet filtering and traffic statistics on real capture-file structures.")

# ---------------------------------------------------------------------------
# References and appendices
# ---------------------------------------------------------------------------
h1("References")
refs = [
    "NetScope project source code. https://github.com/anshika-006/cn-project",
    "J. Postel, “Internet Protocol,” RFC 791, IETF, 1981.",
    "J. Postel, “Internet Control Message Protocol,” RFC 792, IETF, 1981.",
    "J. Postel, “User Datagram Protocol,” RFC 768, IETF, 1980.",
    "W. Eddy (Ed.), “Transmission Control Protocol (TCP),” RFC 9293, IETF, 2022.",
    "D. Plummer, “An Ethernet Address Resolution Protocol,” RFC 826, IETF, 1982.",
    "P. Mockapetris, “Domain Names – Implementation and Specification,” RFC 1035, IETF, 1987.",
    "S. Deering and R. Hinden, “Internet Protocol, Version 6 (IPv6) Specification,” RFC 8200, IETF, 2017.",
    "A. Conta, S. Deering and M. Gupta, “Internet Control Message Protocol (ICMPv6) for IPv6,” RFC 4443, IETF, 2006.",
    "S. Thomson et al., “DNS Extensions to Support IP Version 6,” RFC 3596, IETF, 2003.",
    "Scapy documentation. https://scapy.readthedocs.io",
    "Streamlit documentation. https://docs.streamlit.io",
    "pandas documentation. https://pandas.pydata.org/docs",
    "Wireshark User’s Guide. https://www.wireshark.org/docs/",
]
for i, rtext in enumerate(refs, 1):
    p = doc.add_paragraph()
    p.paragraph_format.left_indent = Cm(0.9)
    p.paragraph_format.first_line_indent = Cm(-0.9)
    p.paragraph_format.space_after = Pt(3)
    p.add_run(f"[{i}]\t{rtext}")

h1("Appendix A: Sample Frame Map")
table_caption("Table 9: Representative frames of the demonstration capture")
table(["Frame(s)", "What the frames show"], [
    ["1–2", "ARP request (Ethernet broadcast, who-has 192.168.1.1) and reply."],
    ["3–4", "IPv4 ICMP echo request (8, 0) and echo reply (0, 0) between 192.168.1.10 and 8.8.8.8."],
    ["11–12", "DNS query and response for example.com (A); #11 is IPv4/UDP/DNS, ports 62779 → 53."],
    ["13–15", "First complete TCP handshake, 192.168.1.10:56299 ↔ 93.184.216.34:443."],
    ["25–27, 37–39, 49–51", "Second, third and fourth complete handshakes (to three other servers on port 443)."],
    ["59–60", "Refused connection: SYN to 192.168.1.1:8080 answered by RST+ACK."],
    ["61–62", "DNS AAAA query and response for example.com, carried over IPv4/UDP."],
    ["65–67", "Plain IPv4/UDP, source port 60000 to destination port 3478; application Other / Not Detected."],
    ["68–71", "IPv6 ICMPv6 echo request (128) and reply (129) between fe80::10 and fe80::1, twice."],
    ["72", "IPv4 ICMP destination unreachable, type 3 code 3, quoting a UDP header."],
], [3.6, 12.4], size=10)

h1("Appendix B: Packet Listing")
para("The complete decoded listing is supplied as `practical_file/appendix/packet_index.csv` (72 rows, "
     "23 columns). It was extracted from the capture with NetScope's parser outside the user interface. "
     "Table 10 is a compact print version with selected columns.", size=11)
table_caption("Table 10: All 72 packets (selected columns from packet_index.csv)")
rows = []
with open(CSV, newline="", encoding="utf-8") as fh:
    for r in csv.DictReader(fh):
        ports = f"{r['src_port']} → {r['dst_port']}" if r["src_port"] else ""
        info = ""
        if r["tcp_flags"]:
            info = r["tcp_flags"]
        elif r["icmp_info"]:
            info = f"{r['icmp_info']} ({r['icmp_type']}/{r['icmp_code']})"
        elif r["arp_operation"]:
            info = r["arp_operation"]
        if r["dns_direction"]:
            info = f"{r['dns_direction']} {r['dns_query']} {r['dns_query_type']}"
        rows.append([r["packet_no"], f"{float(r['relative_time']):.3f}", r["src_ip"], r["dst_ip"],
                     r["protocol"], ports, r["length"], info])
table(["No.", "Time (s)", "Source", "Destination", "Proto", "Ports", "Len", "Info"], rows,
      [0.9, 1.4, 2.6, 2.6, 1.4, 2.6, 1.0, 3.5], size=7.5, align_right=(0, 1, 6))

h1("Appendix C: Figure Files")
table_caption("Table 11: Figure numbers and file names (in practical_file/figures)")
table(["Figure", "File"], [
    ["1", "00_architecture.svg (vector; PNG preview 00_architecture.png)"],
    ["2", "01_startup.png"], ["3", "02_overview.png"], ["4", "02b_top_talkers.png"],
    ["5", "03_packet_explorer_dns_filter.png"], ["6", "04_dns_packet_11.png"],
    ["7", "05_tcp_syn_packet_13.png"], ["8", "05b_handshake_triptych.png"],
    ["9", "06_arp_packet_1.png"], ["10", "07_ipv6_icmpv6_packet_68.png"],
    ["11", "08_layer_distributions.png"], ["12", "09_tcp_flags_and_handshakes.png"],
    ["13", "10_icmp_and_dns_summary.png"], ["14", "11_pcapng_upload.png"], ["15", "12_invalid_file.png"],
    ["16", "15_filter_dns_arp.png"], ["17", "16_filter_no_match.png"], ["18", "14_no_packets.png"],
    ["19", "13_truncated_warning.png"], ["20", "x_packet_61.png"], ["21", "x_packet_65.png"], ["22", "x_packet_72.png"],
], [2.0, 14.0], size=10)

h1("Appendix D: Supplementary Evidence")
figure("15_filter_dns_arp.png", "Figure 16: Protocol filter DNS + ARP with no IP text: 12 of 72 packets "
       "(OR matching within the protocol selection).", crop_h=1320)
figure("16_filter_no_match.png", "Figure 17: Source IP text 198.51.100.254 with no protocol filter: "
       "0 of 72 packets and the no-match message.")
figure("14_no_packets.png", "Figure 18: no_packets.pcap is a valid PCAP file with zero frames and is "
       "reported as containing no packets.")
figure("13_truncated_warning.png", "Figure 19: truncated_demo.pcap: the sidebar warns that the file ends "
       "in the middle of a packet, and the 72 readable packets (10.11 KB) are still analysed.")
figure("x_packet_61.png", "Figure 20: packet #61, a DNS AAAA query for example.com carried over IPv4/UDP.",
       width_cm=13, crop_h=1120)
figure("x_packet_65.png", "Figure 21: packet #65, plain IPv4/UDP to destination port 3478 with application "
       "label Other / Not Detected.", width_cm=13, crop_h=1060)
figure("x_packet_72.png", "Figure 22: packet #72, ICMP destination unreachable (type 3, code 3); the "
       "outer ICMP header sets the transport label.", width_cm=13, crop_h=1330)

# ---------------------------------------------------------------------------
# Footer with page numbers
# ---------------------------------------------------------------------------
for s in doc.sections:
    fp = s.footer.paragraphs[0]
    fp.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = fp.add_run("NetScope – CN Practical File  ·  Page ")
    set_font(r, BODY_FONT, 9.5)
    field(fp, "PAGE", "1")

doc.save(OUT)
print("saved", OUT)
