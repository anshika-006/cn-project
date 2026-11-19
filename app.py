"""
NetScope - Network Traffic Analysis and Packet Analyzer
Streamlit user interface.

Run with:   streamlit run app.py
"""

from __future__ import annotations

import os
import tempfile

import altair as alt  # charting library bundled with Streamlit
import pandas as pd
import streamlit as st

from netscope import filters
from netscope import protocol_analyzer as pa
from netscope import traffic_statistics as ts
from netscope.packet_parser import CaptureFileError, parse_capture

ALLOWED_EXTENSIONS = ("pcap", "pcapng")
SAMPLE_CAPTURE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                              "sample_data", "sample_capture.pcap")
PAGES = ["Overview", "Packet Explorer", "Protocol Analysis", "About Project"]

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

st.set_page_config(page_title="NetScope", page_icon="🔎", layout="wide")


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
    """Sidebar upload widget and sample option. Returns (df, info) or (None, None).

    An uploaded file always takes priority over the built-in sample capture.
    """
    st.sidebar.subheader("Capture file")
    uploaded = st.sidebar.file_uploader(
        "Upload a Wireshark capture",
        type=list(ALLOWED_EXTENSIONS),
        help=f"PCAP or PCAPNG file, up to {max_upload_mb()} MB.",
    )

    st.sidebar.markdown("**No capture file? Try the demo**")
    use_sample = st.sidebar.toggle(
        "Use sample capture",
        key="use_sample",
        disabled=uploaded is not None or not os.path.exists(SAMPLE_CAPTURE),
        help="Loads a built-in demo file (synthetic packets, no real traffic) covering "
             "ARP, IPv4, IPv6, TCP, UDP, ICMP, ICMPv6 and DNS.",
    )

    if uploaded is not None:
        ext = uploaded.name.rsplit(".", 1)[-1].lower() if "." in uploaded.name else ""
        if ext not in ALLOWED_EXTENSIONS:
            st.sidebar.error("Only .pcap and .pcapng files are supported.")
            return None, None
        if uploaded.size > max_upload_mb() * 1024 * 1024:
            st.sidebar.error(f"File is larger than the {max_upload_mb()} MB limit.")
            return None, None
        file_name, file_bytes = uploaded.name, uploaded.getvalue()
    elif use_sample:
        file_name = os.path.basename(SAMPLE_CAPTURE)
        with open(SAMPLE_CAPTURE, "rb") as fh:
            file_bytes = fh.read()
    else:
        return None, None

    try:
        with st.spinner(f"Parsing {file_name} with Scapy..."):
            df, info = analyze_capture(file_bytes, file_name)
    except CaptureFileError as exc:
        st.sidebar.error(str(exc))
        return None, None
    except Exception as exc:  # unexpected problem: report it, do not crash
        st.sidebar.error(f"Unexpected error while reading the file: {exc}")
        return None, None

    label = "sample capture" if uploaded is None else file_name
    st.sidebar.success(
        f"Loaded **{label}**  \n"
        f"{info['packet_count']:,} packets · {info['format'].upper()} format"
    )
    if info["warning"]:
        st.sidebar.warning(info["warning"])
    if info["malformed_count"]:
        st.sidebar.warning(
            f"{info['malformed_count']} packet(s) could not be fully decoded and are "
            "listed as 'Other / Not Detected'."
        )
    return df, info


# ---------------------------------------------------------------------------
# Small UI helpers
# ---------------------------------------------------------------------------
def empty_state():
    st.info("No capture file loaded. Upload a **.pcap** or **.pcapng** file from the sidebar, "
            "or switch on **Use sample capture** to see a demo.")
    st.markdown(
        """
        **How to get a capture file**
        1. Open **Wireshark** and select your network interface (e.g. Wi-Fi or Ethernet).
        2. Start a capture, browse a website or run `ping 8.8.8.8` / `nslookup example.com`, then stop it.
        3. Choose **File → Save As…** and save as *pcapng* or *Wireshark/tcpdump – pcap*.
        4. Upload the saved file using the sidebar.

        Only capture traffic on networks you own or are authorized to analyze.
        """
    )


def bar_chart(data: pd.DataFrame, category: str):
    """Horizontal bar chart, bars in the same order as the rows, x-axis from 0."""
    chart = (
        alt.Chart(data)
        .mark_bar(color="#1f6feb")
        .encode(
            x=alt.X("Packets:Q", title="Packets", scale=alt.Scale(domainMin=0),
                    axis=alt.Axis(tickMinStep=1, format="d")),
            y=alt.Y(f"{category}:N", title=None, sort=list(data[category]), axis=alt.Axis(labelLimit=220)),
            tooltip=list(data.columns),
        )
        .properties(height=alt.Step(30))  # 30 px per bar so every label shows
    )
    st.altair_chart(chart, width="stretch")


def distribution_chart(dist: pd.DataFrame, title: str, hide_zero: bool = False):
    st.markdown(f"**{title}**")
    data = dist[dist["Packets"] > 0] if hide_zero else dist
    if data["Packets"].sum() == 0:
        st.caption("No packets in this category.")
        return
    bar_chart(data, "Protocol")


def top_ip_chart(top: pd.DataFrame, title: str):
    st.markdown(f"**{title}**")
    if top.empty:
        st.caption("No IP addresses found in this capture.")
        return
    bar_chart(top, "IP Address")  # already sorted by count


def key_value_table(rows: list[tuple[str, object]]):
    """Render a two-column Field / Value table, showing '—' for missing values."""
    clean = [(k, "—" if v is None or (not isinstance(v, str) and pd.isna(v)) else str(v)) for k, v in rows]
    st.dataframe(pd.DataFrame(clean, columns=["Field", "Value"]), hide_index=True,
                 width="stretch")


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------
def page_overview(df: pd.DataFrame):
    st.header("Overview")
    st.caption("Summary of every packet in the uploaded capture.")

    s = ts.summary(df)
    cols = st.columns(5)
    cols[0].metric("Total Packets Analyzed", f"{s['total_packets']:,}", border=True)
    cols[1].metric("Total Captured Data", ts.format_bytes(s["total_bytes"]), border=True)
    cols[2].metric("Unique Source IPs", f"{s['unique_src_ips']:,}", border=True)
    cols[3].metric("Unique Destination IPs", f"{s['unique_dst_ips']:,}", border=True)
    cols[4].metric("DNS Packets", f"{s['dns_packets']:,}", border=True)
    st.caption(f"Capture duration: {s['duration']:.3f} seconds")

    st.subheader("Protocol distribution")
    c1, c2, c3 = st.columns(3)
    with c1:
        distribution_chart(pa.network_distribution(df), "Network Layer")
    with c2:
        distribution_chart(pa.transport_distribution(df), "Transport Layer")
    with c3:
        distribution_chart(pa.application_distribution(df), "Application Layer")

    st.subheader("Top talkers")
    c1, c2 = st.columns(2)
    with c1:
        top_ip_chart(ts.top_ips(df, "src_ip"), "Top 5 Source IP Addresses")
    with c2:
        top_ip_chart(ts.top_ips(df, "dst_ip"), "Top 5 Destination IP Addresses")


def page_packet_explorer(df: pd.DataFrame):
    st.header("Packet Explorer")
    st.caption("Filter the packet list and click a row to inspect its metadata.")

    c1, c2, c3 = st.columns([2, 1, 1])
    protocols = c1.multiselect(
        "Protocol", list(filters.PROTOCOL_FILTERS),
        help="Shows packets matching ANY selected protocol.",
    )
    src_ip = c2.text_input("Source IP contains", placeholder="e.g. 192.168.1.5")
    dst_ip = c3.text_input("Destination IP contains", placeholder="e.g. 8.8.8.8")

    view = filters.apply_filters(df, protocols, src_ip, dst_ip)
    st.markdown(f"Showing **{len(view):,}** of **{len(df):,}** packets")

    if view.empty:
        st.warning("No packets match the selected filters.")
        return

    table = view[list(TABLE_COLUMNS)].rename(columns=TABLE_COLUMNS)
    for col in ("Source Port", "Destination Port"):
        table[col] = table[col].astype("string").fillna("")
    event = st.dataframe(
        table, hide_index=True, width="stretch", height=380,
        on_select="rerun", selection_mode="single-row", key="packet_table",
        column_config={
            "Packet No.": st.column_config.NumberColumn(format="%d", width="small"),
            # Ports shown as plain text so that "no port" (ARP, ICMP) appears blank.
            "Source Port": st.column_config.TextColumn(),
            "Destination Port": st.column_config.TextColumn(),
            "Packet Length": st.column_config.NumberColumn(format="%d bytes"),
        },
    )

    selected_rows = event.selection.rows if event and event.selection else []
    if selected_rows:
        packet = view.iloc[selected_rows[0]]
    else:
        number = st.number_input(
            "Or enter a packet number to inspect", min_value=1, max_value=len(df),
            value=int(view.iloc[0]["packet_no"]), step=1,
        )
        packet = df[df["packet_no"] == number].iloc[0]

    show_packet_details(packet)


def show_packet_details(p: pd.Series):
    st.subheader(f"Packet #{int(p['packet_no'])} details")
    if p["parse_error"]:
        st.warning(p["parse_error"])

    c1, c2 = st.columns(2)
    with c1:
        st.markdown("**Frame**")
        key_value_table([
            ("Packet number", int(p["packet_no"])),
            ("Timestamp", p["time"]),
            ("Time since first packet (s)", p["relative_time"]),
            ("Packet length", f"{int(p['length'])} bytes"),
        ])
        st.markdown("**Data Link Layer (Ethernet)**")
        key_value_table([("Source MAC", p["src_mac"]), ("Destination MAC", p["dst_mac"])])
        st.markdown("**Network Layer**")
        rows = [("Protocol", p["network_protocol"]),
                ("Source IP", p["src_ip"]), ("Destination IP", p["dst_ip"])]
        if p["network_protocol"] == "ARP":
            rows.append(("ARP operation", p["arp_operation"]))
        key_value_table(rows)
    with c2:
        st.markdown("**Transport Layer**")
        rows = [("Protocol", p["transport_protocol"]),
                ("Source port", p["src_port"]), ("Destination port", p["dst_port"])]
        if p["transport_protocol"] == "TCP":
            rows += [("TCP flags", p["tcp_flags"] or "(none)"),
                     ("Sequence number", p["tcp_seq"]),
                     ("Acknowledgement number", p["tcp_ack"])]
        if p["transport_protocol"] in ("ICMP", "ICMPv6"):
            rows += [("ICMP type", p["icmp_type"]), ("ICMP code", p["icmp_code"]),
                     ("Message", p["icmp_info"])]
        key_value_table(rows)
        st.markdown("**Application Layer**")
        rows = [("Protocol", p["application_protocol"])]
        if p["application_protocol"] == "DNS":
            rows += [("DNS message", p["dns_direction"]),
                     ("Query domain", p["dns_query"]),
                     ("Query type", p["dns_query_type"])]
        key_value_table(rows)
    st.caption("Only header metadata is shown. Application payload contents are not displayed or stored.")


def page_protocol_analysis(df: pd.DataFrame):
    st.header("Protocol Analysis")
    st.caption(
        "Each packet is classified separately at the network, transport and application "
        "layer, so every table below adds up to the total number of packets."
    )

    for (layer, dist), col in zip(pa.layer_distributions(df).items(), st.columns(3)):
        with col:
            st.subheader(layer)
            st.dataframe(dist, hide_index=True, width="stretch",
                         column_config={"Percentage": st.column_config.NumberColumn(format="%.2f %%")})
            distribution_chart(dist, f"{layer} packets", hide_zero=True)

    st.divider()
    st.subheader("TCP analysis")
    c1, c2 = st.columns(2)
    with c1:
        st.markdown("**TCP flag combinations**")
        flags = ts.tcp_flag_counts(df)
        if flags.empty:
            st.caption("No TCP packets in this capture.")
        else:
            st.dataframe(flags, hide_index=True, width="stretch")
    with c2:
        st.markdown("**Completed three-way handshakes (SYN → SYN-ACK → ACK)**")
        hs = ts.find_tcp_handshakes(df)
        if hs.empty:
            st.caption("No complete TCP handshakes found.")
        else:
            st.caption(f"{len(hs)} handshake(s) found")
            st.dataframe(hs, hide_index=True, width="stretch")

    st.divider()
    c1, c2 = st.columns(2)
    with c1:
        st.subheader("ICMP / ICMPv6 messages")
        icmp = ts.icmp_type_counts(df)
        if icmp.empty:
            st.caption("No ICMP or ICMPv6 packets in this capture.")
        else:
            st.dataframe(icmp, hide_index=True, width="stretch")
    with c2:
        st.subheader("Top queried DNS domains")
        dns = ts.top_dns_queries(df)
        if dns.empty:
            st.caption("No DNS queries in this capture.")
        else:
            st.dataframe(dns, hide_index=True, width="stretch")

    with st.expander("How classification works"):
        st.markdown(
            f"""
            - **Network layer** — IPv4, IPv6 or ARP, from the outermost decoded header.
              ARP has no IP header; its sender/target IP fields are used as addresses.
            - **Transport layer** — TCP, UDP, ICMP or ICMPv6. ARP is *{pa.NOT_APPLICABLE}*
              because it has no transport layer. IP packets carrying other protocols
              (e.g. IGMP, GRE, or fragments) are *{pa.OTHER}*.
            - **Application layer** — DNS is detected only when Scapy decodes a valid DNS
              header, not merely because port 53 is used. Other application protocols
              (HTTP, TLS…) are **not** guessed from port numbers and are shown as *{pa.OTHER}*.
            """
        )


def page_about():
    st.header("About Project")
    st.markdown(
        """
        **NetScope – Network Traffic Analysis and Packet Analyzer** is a Computer Networks
        mini-project. It reads packets captured with **Wireshark** and analyzes them offline
        using **Scapy**, then presents the results in this **Streamlit** dashboard.

        #### Workflow
        1. Capture traffic in Wireshark on a network you are authorized to analyze.
        2. Save it as a PCAP or PCAPNG file.
        3. Upload the file here. Scapy decodes each packet layer by layer.
        4. NetScope extracts metadata (addresses, ports, flags, DNS names) and computes statistics.

        #### Concepts demonstrated
        - Packet structure and the layered TCP/IP model
        - Ethernet MAC addressing and ARP
        - IPv4 and IPv6 addressing
        - TCP (flags, three-way handshake) and UDP
        - ICMP / ICMPv6 (e.g. ping echo request and reply)
        - DNS name resolution

        #### Technologies
        Python · Scapy · Pandas · Streamlit · Wireshark

        #### Privacy
        All processing happens locally. The uploaded file is written to a temporary file only
        while it is parsed and is then deleted. Application payloads are never displayed.
        """
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    st.sidebar.title("🔎 NetScope")
    st.sidebar.caption("Network Traffic Analysis and Packet Analyzer")
    page = st.sidebar.radio("Navigation", PAGES, label_visibility="collapsed")
    st.sidebar.divider()

    df, _info = handle_upload()

    if page == "About Project":
        page_about()
        return
    if df is None:
        st.header(page)
        empty_state()
        return

    {"Overview": page_overview,
     "Packet Explorer": page_packet_explorer,
     "Protocol Analysis": page_protocol_analysis}[page](df)


if __name__ == "__main__":
    main()
