"""
NetScope - Network Traffic Analysis and Packet Analyzer
Streamlit user interface.

Run with:   streamlit run app.py

The look and feel (colours, cards, charts) lives in netscope/ui.py;
this file only decides what to show on each page.
"""

from __future__ import annotations

import os
import tempfile
from html import escape

import pandas as pd
import streamlit as st

from netscope import filters
from netscope import protocol_analyzer as pa
from netscope import traffic_statistics as ts
from netscope import ui
from netscope.packet_parser import CaptureFileError, parse_capture

APP_DIR = os.path.dirname(os.path.abspath(__file__))
ALLOWED_EXTENSIONS = ("pcap", "pcapng")
SAMPLE_CAPTURE = os.path.join(APP_DIR, "sample_data", "sample_capture.pcap")
# Built-in demo files (label -> path). "?demo=1" opens the first, "?demo=web" the second.
SAMPLES = {
    "Mixed protocols (72 packets)": SAMPLE_CAPTURE,
    "Web traffic: HTTP, TLS, retransmissions": os.path.join(APP_DIR, "sample_data", "web_demo_capture.pcap"),
}
SAMPLE_KEYS = {"1": "Mixed protocols (72 packets)", "web": "Web traffic: HTTP, TLS, retransmissions"}
LOGO = os.path.join(APP_DIR, "assets", "logo.svg")
LOGO_MARK = os.path.join(APP_DIR, "assets", "mark.svg")

# Table column names shown to the user (internal name -> display name).
TABLE_COLUMNS = {
    "packet_no": "Packet No.",
    "time": "Timestamp",
    "src_ip": "Source IP",
    "dst_ip": "Destination IP",
    "protocol": "Protocol",
    "src_port": "Source Port",
    "dst_port": "Destination Port",
    "length": "Packet Length",
}

st.set_page_config(page_title="NetScope · Packet Analyzer", page_icon=LOGO_MARK, layout="wide")


def max_upload_mb() -> int:
    """Upload limit, taken from .streamlit/config.toml (server.maxUploadSize)."""
    return int(st.get_option("server.maxUploadSize"))


# ---------------------------------------------------------------------------
# Capture processing
# ---------------------------------------------------------------------------
@st.cache_data(show_spinner=False, max_entries=3)
def analyze_capture(file_bytes: bytes, file_name: str):
    """Write the upload to a temporary file, parse it, then delete the file.

    The result is cached in memory for this session so switching pages does not
    re-parse the capture. The capture file itself is never kept on disk.
    """
    suffix = os.path.splitext(file_name)[1].lower() or ".pcap"
    fd, tmp_path = tempfile.mkstemp(suffix=suffix, prefix="netscope_")
    try:
        with os.fdopen(fd, "wb") as tmp:
            tmp.write(file_bytes)
        return parse_capture(tmp_path)
    finally:
        try:
            os.remove(tmp_path)
        except OSError:
            pass


def handle_upload():
    """Sidebar upload widget and sample option.

    Returns (df, info, file_name) or (None, None, None). An uploaded file always
    takes priority over the built-in sample capture.
    """
    ui.side_label("Capture file")
    uploaded = st.sidebar.file_uploader(
        "Upload a Wireshark capture",
        type=list(ALLOWED_EXTENSIONS),
        help=f"PCAP or PCAPNG file, up to {max_upload_mb()} MB.",
        label_visibility="collapsed",
    )

    ui.side_label("No capture file? Try the demo")
    # Remember the demo choice in the URL (?demo=1 or ?demo=web) so a page refresh keeps it.
    if "use_sample" not in st.session_state:
        st.session_state.use_sample = st.query_params.get("demo") in SAMPLE_KEYS
        st.session_state.sample_choice = SAMPLE_KEYS.get(st.query_params.get("demo"), next(iter(SAMPLES)))
    use_sample = st.sidebar.toggle(
        "Use sample capture",
        key="use_sample",
        disabled=uploaded is not None or not os.path.exists(SAMPLE_CAPTURE),
        help="Loads a built-in demo file (synthetic packets, no real traffic). The mixed file covers "
             "ARP, IPv4, IPv6, TCP, UDP, ICMP, ICMPv6 and DNS; the web file covers HTTP, TLS "
             "(with SNI), TCP retransmissions and RTT.",
    )
    sample_path = SAMPLE_CAPTURE
    if use_sample and uploaded is None:
        choice = st.sidebar.selectbox("Demo file", list(SAMPLES), key="sample_choice",
                                      label_visibility="collapsed")
        if not os.path.exists(SAMPLES[choice]):
            choice = next(iter(SAMPLES))
        sample_path = SAMPLES[choice]
        st.query_params["demo"] = next(k for k, v in SAMPLE_KEYS.items() if v == choice)
    elif "demo" in st.query_params:
        del st.query_params["demo"]

    if uploaded is not None:
        ext = uploaded.name.rsplit(".", 1)[-1].lower() if "." in uploaded.name else ""
        if ext not in ALLOWED_EXTENSIONS:
            st.sidebar.error("Only .pcap and .pcapng files are supported.")
            return None, None, None
        if uploaded.size > max_upload_mb() * 1024 * 1024:
            st.sidebar.error(f"File is larger than the {max_upload_mb()} MB limit.")
            return None, None, None
        file_name, file_bytes = uploaded.name, uploaded.getvalue()
    elif use_sample:
        file_name = os.path.basename(sample_path)
        with open(sample_path, "rb") as fh:
            file_bytes = fh.read()
    else:
        return None, None, None

    try:
        with st.spinner(f"Parsing {file_name} with Scapy..."):
            df, info = analyze_capture(file_bytes, file_name)
    except CaptureFileError as exc:
        st.sidebar.error(str(exc))
        return None, None, None
    except Exception as exc:  # unexpected problem: report it, do not crash
        st.sidebar.error(f"Unexpected error while reading the file: {exc}")
        return None, None, None

    ui.side_label("Active capture")
    ui.file_card(file_name, info["packet_count"], info["format"], is_sample=uploaded is None)
    if info["warning"]:
        st.sidebar.warning(info["warning"])
    if info["malformed_count"]:
        st.sidebar.warning(
            f"{info['malformed_count']} packet(s) could not be fully decoded and are "
            "listed as 'Other / Not Detected'."
        )
    return df, info, file_name


# The capture loaded for this run (set in main(), read by the page functions).
CAPTURE: dict = {"df": None, "info": None, "name": None}


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------
def capture_chips(df: pd.DataFrame) -> list[tuple[str, str]]:
    s = ts.summary(df)
    return [
        ("file", f"<b>{escape(str(CAPTURE['name']))}</b>"),
        ("clock", f"{s['duration']:.2f} s span"),
    ]


def card(key: str):
    """A white rounded card (styled in ui.py via the 'card' key prefix)."""
    return st.container(key=f"card_{key}")


def distribution_card(key: str, dist: pd.DataFrame, title: str, subtitle: str, hide_zero: bool = False):
    color = ui.LAYER_COLORS.get(title, ui.PRIMARY)
    with card(key):
        ui.card_title(title, subtitle, color)
        data = dist[dist["Packets"] > 0] if hide_zero else dist
        if data["Packets"].sum() == 0:
            ui.muted("No packets in this category.")
        else:
            ui.bar_chart(data, "Protocol", color)


def top_ip_card(key: str, top: pd.DataFrame, title: str, subtitle: str, color: str):
    with card(key):
        ui.card_title(title, subtitle, color)
        if top.empty:
            ui.muted("No IP addresses found in this capture.")
        else:
            ui.bar_chart(top, "IP Address", color)  # already sorted by count


def no_capture(eyebrow: str, title: str, subtitle: str):
    ui.page_header(eyebrow, title, subtitle)
    ui.empty_state()
    ui.footer()


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------
def page_overview():
    df = CAPTURE["df"]
    if df is None:
        return no_capture("Dashboard", "Overview",
                          "A high-level summary of every packet in your capture.")

    ui.page_header("Dashboard", "Overview",
                   "A high-level summary of every packet in your capture.", capture_chips(df))

    s = ts.summary(df)
    size_value, size_unit = ts.format_bytes(s["total_bytes"]).split(" ", 1)
    ui.kpi_row([
        {"label": "Packets analyzed", "value": f"{s['total_packets']:,}", "icon": "packets",
         "color": ui.PRIMARY, "foot": "Every frame in the file"},
        {"label": "Captured data", "value": size_value, "unit": size_unit, "icon": "data",
         "color": "#7A5AF8", "foot": "Sum of frame lengths"},
        {"label": "Source IPs", "value": f"{s['unique_src_ips']:,}", "icon": "source",
         "color": "#0E9F8E", "foot": "Unique senders"},
        {"label": "Destination IPs", "value": f"{s['unique_dst_ips']:,}", "icon": "destination",
         "color": "#F59E0B", "foot": "Unique receivers"},
        {"label": "DNS packets", "value": f"{s['dns_packets']:,}", "icon": "dns",
         "color": "#E5484D", "foot": "Queries and responses"},
    ])

    ui.section("Traffic over time", "How many packets (or bytes) were captured in each time interval.")
    with card("time"):
        interval = ts.choose_interval(s["duration"])
        c1, c2 = st.columns([3, 1])
        with c1:
            ui.card_title("Traffic rate", f"Grouped into {interval:g}-second intervals", ui.PRIMARY)
        metric = c2.segmented_control("Show", ["Packets", "Bytes"], default="Packets",
                                      key="time_metric", label_visibility="collapsed") or "Packets"
        ui.time_chart(ts.traffic_over_time(df, interval), metric, interval)

    ui.section("Protocol distribution",
               "Each packet is classified once per layer of the TCP/IP model. Grey bars are packets "
               "that do not belong to a recognised protocol at that layer.")
    c1, c2, c3 = st.columns(3, gap="small")
    with c1:
        distribution_card("net", pa.network_distribution(df), "Network Layer", "IPv4 · IPv6 · ARP")
    with c2:
        distribution_card("tra", pa.transport_distribution(df), "Transport Layer", "TCP · UDP · ICMP · ICMPv6")
    with c3:
        distribution_card("app", pa.application_distribution(df), "Application Layer",
                          "DNS · HTTP · TLS (decoded headers)")

    ui.section("Top talkers", "The hosts that sent and received the most packets.")
    c1, c2 = st.columns(2, gap="small")
    with c1:
        top_ip_card("src", ts.top_ips(df, "src_ip"), "Top source IPs", "Top 5 by packets sent",
                    ui.TALKER_COLORS["src"])
    with c2:
        top_ip_card("dst", ts.top_ips(df, "dst_ip"), "Top destination IPs", "Top 5 by packets received",
                    ui.TALKER_COLORS["dst"])
    ui.footer()


def page_packet_explorer():
    df = CAPTURE["df"]
    if df is None:
        return no_capture("Inspect", "Packet Explorer",
                          "Filter the packet list and drill into any packet layer by layer.")

    ui.page_header("Inspect", "Packet Explorer",
                   "Filter the packet list, then select a row to inspect its headers layer by layer.",
                   capture_chips(df))

    with card("filters"):
        c1, c2, c3 = st.columns([2, 1, 1])
        protocols = c1.multiselect(
            "Protocol", list(filters.PROTOCOL_FILTERS), placeholder="All protocols",
            help="Shows packets matching ANY selected protocol.",
        )
        src_ip = c2.text_input("Source IP contains", placeholder="e.g. 192.168.1.5")
        dst_ip = c3.text_input("Destination IP contains", placeholder="e.g. 8.8.8.8")

    view = filters.apply_filters(df, protocols, src_ip, dst_ip)

    with card("table"):
        c1, c2 = st.columns([3, 1], vertical_alignment="center")
        with c1:
            ui.card_title("Packets", f"Showing {len(view):,} of {len(df):,} packets · click a row to inspect it")
        stem = os.path.splitext(str(CAPTURE["name"]))[0]
        c2.download_button(
            "Export CSV", data=filters.to_csv(view), file_name=f"{stem}_packets.csv",
            mime="text/csv", icon=":material/download:", width="stretch",
            disabled=view.empty, help="Download the metadata of the packets shown below "
                                      "(all columns, after filters). No payload bytes are included.",
        )
        if view.empty:
            ui.muted("No packets match the selected filters. Try clearing a filter above.")
            ui.footer()
            return
        table = view[list(TABLE_COLUMNS)].rename(columns=TABLE_COLUMNS)
        for col in ("Source Port", "Destination Port"):
            table[col] = table[col].astype("string").fillna("")
        event = st.dataframe(
            table, hide_index=True, width="stretch", height=400,
            on_select="rerun", selection_mode="single-row", key="packet_table",
            column_config={
                "Packet No.": st.column_config.NumberColumn("No.", format="%d", width="small"),
                # Ports shown as plain text so that "no port" (ARP, ICMP) appears blank.
                "Source Port": st.column_config.TextColumn(),
                "Destination Port": st.column_config.TextColumn(),
                "Packet Length": st.column_config.NumberColumn("Length", format="%d B"),
            },
        )
        selected_rows = event.selection.rows if event and event.selection else []
        if selected_rows:
            packet = view.iloc[selected_rows[0]]
        else:
            c1, _ = st.columns([1, 3])
            number = c1.number_input(
                "Or enter a packet number to inspect", min_value=1, max_value=len(df),
                value=int(view.iloc[0]["packet_no"]), step=1,
            )
            packet = df[df["packet_no"] == number].iloc[0]

    show_packet_details(packet)
    ui.footer()


def show_packet_details(p: pd.Series):
    ui.section(f"Packet #{int(p['packet_no'])}",
               "Header metadata decoded by Scapy, from the outermost layer inwards. "
               "Application payloads are never displayed or stored.")
    if p["parse_error"]:
        st.warning(p["parse_error"])

    c1, c2 = st.columns(2, gap="small")
    with c1, card("frame"):
        ui.card_title("Frame", "Capture metadata", "#475569")
        ui.kv_list([
            ("Packet number", int(p["packet_no"])),
            ("Timestamp", p["time"]),
            ("Time since first packet (s)", p["relative_time"]),
            ("Packet length", f"{int(p['length'])} bytes"),
        ])
    with c2, card("eth"):
        ui.card_title("Data Link Layer", "Ethernet", "#94A3B8")
        ui.kv_list([("Source MAC", p["src_mac"]), ("Destination MAC", p["dst_mac"])])

    c1, c2, c3 = st.columns(3, gap="small")
    with c1, card("netl"):
        ui.card_title("Network Layer", str(p["network_protocol"]), ui.LAYER_COLORS["Network Layer"])
        rows = [("Protocol", p["network_protocol"]),
                ("Source IP", p["src_ip"]), ("Destination IP", p["dst_ip"])]
        if p["network_protocol"] == "ARP":
            rows.append(("ARP operation", p["arp_operation"]))
        ui.kv_list(rows)
    with c2, card("tral"):
        ui.card_title("Transport Layer", str(p["transport_protocol"]), ui.LAYER_COLORS["Transport Layer"])
        rows = [("Protocol", p["transport_protocol"]),
                ("Source port", p["src_port"]), ("Destination port", p["dst_port"])]
        if p["transport_protocol"] == "TCP":
            rows += [("TCP flags", p["tcp_flags"] or "(none)"),
                     ("Sequence number", p["tcp_seq"]),
                     ("Acknowledgement number", p["tcp_ack"]),
                     ("Payload length", f"{int(p['tcp_payload_len'])} bytes"
                      if pd.notna(p["tcp_payload_len"]) else None)]
        if p["transport_protocol"] in ("ICMP", "ICMPv6"):
            rows += [("ICMP type", p["icmp_type"]), ("ICMP code", p["icmp_code"]),
                     ("Message", p["icmp_info"])]
        ui.kv_list(rows)
    with c3, card("appl"):
        ui.card_title("Application Layer", str(p["application_protocol"]),
                      ui.LAYER_COLORS["Application Layer"])
        rows = [("Protocol", p["application_protocol"])]
        if p["application_protocol"] == "DNS":
            rows += [("DNS message", p["dns_direction"]),
                     ("Query domain", p["dns_query"]),
                     ("Query type", p["dns_query_type"])]
        elif p["application_protocol"] == "HTTP":
            is_request = str(p["http_info"]).split(" ")[0] in pa.HTTP_METHODS
            rows += [("HTTP message", "Request" if is_request else "Response"),
                     ("Request line" if is_request else "Status", p["http_info"])]
            if is_request:
                rows.append(("Host", p["http_host"]))
        elif p["application_protocol"] == "TLS":
            rows += [("TLS records", p["tls_message"]), ("Version", p["tls_version"])]
            if p["tls_sni"]:
                rows.append(("Server name (SNI)", p["tls_sni"]))
        ui.kv_list(rows)


def page_protocol_analysis():
    df = CAPTURE["df"]
    if df is None:
        return no_capture("Analyze", "Protocol Analysis",
                          "Layer-by-layer protocol breakdown, TCP handshakes, ICMP and DNS activity.")

    ui.page_header("Analyze", "Protocol Analysis",
                   "Each packet is classified separately at the network, transport and application "
                   "layer, so every table adds up to the total number of packets.", capture_chips(df))

    subtitles = {"Network Layer": "IPv4 · IPv6 · ARP", "Transport Layer": "TCP · UDP · ICMP · ICMPv6",
                 "Application Layer": "DNS · HTTP · TLS (decoded headers)"}
    cols = st.columns(3, gap="small")
    for i, ((layer, dist), col) in enumerate(zip(pa.layer_distributions(df).items(), cols)):
        with col, card(f"layer{i}"):
            ui.card_title(layer, subtitles.get(layer, ""), ui.LAYER_COLORS.get(layer))
            st.dataframe(dist, hide_index=True, width="stretch",
                         column_config={"Percentage": st.column_config.ProgressColumn(
                             "Share", format="%.1f%%", min_value=0, max_value=100)})

    ui.section("TCP analysis", "Flag combinations and connections that completed the three-way handshake.")
    c1, c2 = st.columns(2, gap="small")
    with c1, card("flags"):
        ui.card_title("TCP flag combinations", "How often each flag set appears", ui.LAYER_COLORS["Transport Layer"])
        flags = ts.tcp_flag_counts(df)
        if flags.empty:
            ui.muted("No TCP packets in this capture.")
        else:
            st.dataframe(flags, hide_index=True, width="stretch")
    with c2, card("hs"):
        hs = ts.find_tcp_handshakes(df)
        ui.card_title("Three-way handshakes",
                      f"SYN → SYN-ACK → ACK · {len(hs)} found" if not hs.empty else "SYN → SYN-ACK → ACK",
                      "#12B76A")
        if hs.empty:
            ui.muted("No complete TCP handshakes found.")
        else:
            st.dataframe(hs, hide_index=True, width="stretch",
                         column_config={"Handshake RTT (ms)": st.column_config.NumberColumn(
                             "RTT (ms)", format="%.3f",
                             help="Time from the SYN to the SYN-ACK: one round trip to the server.")})

    with card("retx"):
        retx = ts.tcp_retransmissions(df)
        ui.card_title("Retransmissions",
                      f"Segments sent again with the same sequence number · {len(retx)} found",
                      "#E5484D")
        if retx.empty:
            ui.muted("No retransmitted TCP segments in this capture.")
        else:
            st.dataframe(retx, hide_index=True, width="stretch")
    st.write("")
    with card("rtt"):
        rtt = ts.tcp_rtt(df)
        ui.card_title("Round-trip time per connection",
                      "Time from a segment to the ACK that covers it (retransmitted segments skipped)",
                      "#12B76A")
        if rtt.empty:
            ui.muted("No TCP connections in this capture.")
        else:
            st.dataframe(rtt, hide_index=True, width="stretch",
                         column_config={c: st.column_config.NumberColumn(c, format="%.3f")
                                        for c in ("Min RTT (ms)", "Avg RTT (ms)", "Max RTT (ms)")})

    ui.section("Web traffic", "HTTP requests and TLS server names, read from the protocol headers.")
    c1, c2 = st.columns(2, gap="small")
    with c1, card("http"):
        ui.card_title("HTTP requests", "Request line, Host header and the server's status reply",
                      ui.LAYER_COLORS["Application Layer"])
        http = ts.http_requests(df)
        if http.empty:
            ui.muted("No HTTP requests in this capture.")
        else:
            st.dataframe(http, hide_index=True, width="stretch")
    with c2, card("tls"):
        ui.card_title("TLS server names", "SNI host names sent in TLS Client Hello messages",
                      ui.LAYER_COLORS["Application Layer"])
        sni = ts.tls_server_names(df)
        if sni.empty:
            ui.muted("No TLS Client Hello messages in this capture.")
        else:
            st.dataframe(sni, hide_index=True, width="stretch")

    ui.section("Conversations", "Packets and bytes exchanged between each pair of IP addresses "
                                "(A is the address that sent first).")
    with card("conv"):
        conv = ts.conversations(df)
        ui.card_title("IP conversations", f"{len(conv)} address pairs", ui.PRIMARY)
        if conv.empty:
            ui.muted("No IPv4 or IPv6 packets in this capture.")
        else:
            st.dataframe(conv, hide_index=True, width="stretch",
                         column_config={c: st.column_config.NumberColumn(c, format="%d B")
                                        for c in ("Bytes", "Bytes A→B", "Bytes B→A")})

    ui.section("Control & name resolution", "ICMP messages (e.g. ping) and the most queried domains.")
    c1, c2 = st.columns(2, gap="small")
    with c1, card("icmp"):
        ui.card_title("ICMP / ICMPv6 messages", "Echo, unreachable and other control messages", "#F59E0B")
        icmp = ts.icmp_type_counts(df)
        if icmp.empty:
            ui.muted("No ICMP or ICMPv6 packets in this capture.")
        else:
            st.dataframe(icmp, hide_index=True, width="stretch")
    with c2, card("dns"):
        ui.card_title("Top queried DNS domains", "Names looked up in DNS queries", ui.LAYER_COLORS["Application Layer"])
        dns = ts.top_dns_queries(df)
        if dns.empty:
            ui.muted("No DNS queries in this capture.")
        else:
            st.dataframe(dns, hide_index=True, width="stretch")

    st.write("")
    with st.expander("How classification works", icon=":material/info:"):
        st.markdown(
            f"""
            - **Network layer**: IPv4, IPv6 or ARP, from the outermost decoded header.
              ARP has no IP header; its sender/target IP fields are used as addresses.
            - **Transport layer**: TCP, UDP, ICMP or ICMPv6. ARP is *{pa.NOT_APPLICABLE}*
              because it has no transport layer. IP packets carrying other protocols
              (e.g. IGMP, GRE, or fragments) are *{pa.OTHER}*.
            - **Application layer**: DNS is detected only when Scapy decodes a valid DNS
              header, not merely because port 53 is used. HTTP is detected from a valid
              request line (e.g. `GET / HTTP/1.1`) or status line (`HTTP/1.1 200 OK`), and
              TLS from a valid record header (content type 20–23, version 3.x); the SNI name
              is read from the Client Hello. Ports are **never** used to guess a protocol, so
              encrypted or unrecognised payloads are shown as *{pa.OTHER}*.
            - **Retransmission**: a TCP segment that repeats a sequence number already sent
              with data (or SYN/FIN) in the same direction.
            - **RTT**: time from a segment to the first ACK that acknowledges it;
              retransmitted segments are skipped (Karn's algorithm).
            """
        )
    ui.footer()


def page_about():
    ui.page_header("Project", "About NetScope",
                   "A Computer Networks mini-project that reads packets captured with Wireshark, "
                   "analyzes them offline with Scapy and presents the results in this dashboard.")
    st.html("""
    <div class="ns-grid2">
      <div class="ns-tile"><h4>Workflow</h4><ol>
        <li>Capture traffic in Wireshark on a network you are authorized to analyze.</li>
        <li>Save it as a PCAP or PCAPNG file.</li>
        <li>Upload the file here. Scapy decodes each packet layer by layer.</li>
        <li>NetScope extracts metadata (addresses, ports, flags, DNS names) and computes statistics.</li>
      </ol></div>
      <div class="ns-tile"><h4>Concepts demonstrated</h4><ol>
        <li>Packet structure and the layered TCP/IP model</li>
        <li>Ethernet MAC addressing and ARP</li>
        <li>IPv4 and IPv6 addressing</li>
        <li>TCP (flags, three-way handshake) and UDP</li>
        <li>ICMP / ICMPv6 (e.g. ping echo request and reply)</li>
        <li>DNS name resolution</li>
        <li>HTTP requests and TLS handshakes (SNI)</li>
        <li>TCP retransmission and round-trip time</li>
      </ol></div>
      <div class="ns-tile"><h4>Technologies</h4><div class="ns-tags">
        <span class="ns-tag">Python</span><span class="ns-tag">Scapy</span><span class="ns-tag">Pandas</span>
        <span class="ns-tag">Streamlit</span><span class="ns-tag">Altair</span><span class="ns-tag">Wireshark</span>
      </div></div>
      <div class="ns-tile"><h4>Privacy</h4><p style="margin:0">All processing happens locally. An uploaded
        file is written to a temporary file only while it is parsed and is then deleted. Application
        payloads are never displayed.</p></div>
    </div>""")
    ui.footer()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    ui.inject_css()
    st.logo(LOGO, icon_image=LOGO_MARK, size="large")

    nav = st.navigation({
        "Analyze": [
            # The default page is always served at "/", so it gets no url_path.
            st.Page(page_overview, title="Overview", icon=":material/space_dashboard:", default=True),
            st.Page(page_packet_explorer, title="Packet Explorer", icon=":material/manage_search:",
                    url_path="packets"),
            st.Page(page_protocol_analysis, title="Protocol Analysis", icon=":material/lan:",
                    url_path="protocols"),
        ],
        "Project": [
            st.Page(page_about, title="About", icon=":material/info:", url_path="about"),
        ],
    })

    df, info, name = handle_upload()
    CAPTURE.update(df=df, info=info, name=name)
    nav.run()


if __name__ == "__main__":
    main()
