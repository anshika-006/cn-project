"""
TraceNet design system for the Streamlit interface (light mode only).

Everything visual lives here: colour tokens, the global stylesheet, and small
HTML components (page header, KPI tiles, cards, empty state). app.py only
decides WHAT to show; this module decides HOW it looks.

Only static markup and escaped values are rendered as HTML; packet payloads
are never displayed.
"""

from __future__ import annotations

import base64
from html import escape

import altair as alt
import pandas as pd
import streamlit as st

# ---------------------------------------------------------------------------
# Design tokens (keep in sync with .streamlit/config.toml)
# ---------------------------------------------------------------------------
INK = "#0B1220"
TEXT = "#1E293B"
MUTED = "#64748B"
SUBTLE = "#94A3B8"
BORDER = "#E6E9F0"
PAGE = "#F6F7FB"
PRIMARY = "#3554F5"
PRIMARY_SOFT = "#EEF1FF"
NEUTRAL_BAR = "#D5DBE6"

# One colour per TCP/IP layer, used consistently in every chart and badge.
LAYER_COLORS = {
    "Network Layer": "#3554F5",      # cobalt
    "Transport Layer": "#7A5AF8",    # violet
    "Application Layer": "#0E9F8E",  # teal
}
TALKER_COLORS = {"src": "#3554F5", "dst": "#0E9F8E"}

FONT = "Inter, system-ui, -apple-system, 'Segoe UI', sans-serif"

# Small stroke icons (24x24 grid, drawn for this project).
_ICONS = {
    "packets": '<path d="M12 3 3 7.5 12 12l9-4.5L12 3Z"/><path d="m3 12 9 4.5 9-4.5"/><path d="m3 16.5 9 4.5 9-4.5"/>',
    "data": '<ellipse cx="12" cy="5.5" rx="8" ry="2.5"/><path d="M4 5.5v6c0 1.4 3.6 2.5 8 2.5s8-1.1 8-2.5v-6"/><path d="M4 11.5v6c0 1.4 3.6 2.5 8 2.5s8-1.1 8-2.5v-6"/>',
    "source": '<circle cx="6" cy="18" r="2.5"/><path d="M8 16 19 5"/><path d="M11 5h8v8"/>',
    "destination": '<circle cx="18" cy="6" r="2.5"/><path d="M16 8 5 19"/><path d="M13 19H5v-8"/>',
    "dns": '<circle cx="12" cy="12" r="9"/><path d="M3 12h18"/><path d="M12 3c2.5 2.6 3.8 5.6 3.8 9s-1.3 6.4-3.8 9c-2.5-2.6-3.8-5.6-3.8-9S9.5 5.6 12 3Z"/>',
    "clock": '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
    "file": '<path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8l-5-5Z"/><path d="M14 3v5h5"/>',
    "upload": '<path d="M12 15V4"/><path d="m7 9 5-5 5 5"/><path d="M5 15v3a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2v-3"/>',
    "spark": '<path d="M12 3v4M12 17v4M3 12h4M17 12h4M5.6 5.6l2.8 2.8M15.6 15.6l2.8 2.8M5.6 18.4l2.8-2.8M15.6 8.4l2.8-2.8"/>',
    "shield": '<path d="M12 3 4.5 6v5.5c0 4.6 3.2 8.4 7.5 9.5 4.3-1.1 7.5-4.9 7.5-9.5V6L12 3Z"/><path d="m9 12 2 2 4-4"/>',
    "wave": '<path d="M2 12h3l3-7 4 14 3-9 2 2h5"/>',
}


def icon(name: str, size: int = 18, color: str = MUTED) -> str:
    """Return an icon as an <img> data URI (st.html strips inline <svg> tags)."""
    svg = (f'<svg xmlns="http://www.w3.org/2000/svg" width="{size}" height="{size}" viewBox="0 0 24 24" '
           f'fill="none" stroke="{color}" stroke-width="1.8" stroke-linecap="round" '
           f'stroke-linejoin="round">{_ICONS[name]}</svg>')
    uri = "data:image/svg+xml;base64," + base64.b64encode(svg.encode()).decode()
    return f'<img src="{uri}" width="{size}" height="{size}" alt="" style="display:block;flex:none">'


# ---------------------------------------------------------------------------
# Global stylesheet
# ---------------------------------------------------------------------------
_CSS = f"""
<style>
/* ---------- canvas ---------- */
.stApp {{ background: {PAGE}; }}
[data-testid="stHeader"] {{ background: transparent; }}
[data-testid="stMainBlockContainer"], .block-container {{
  max-width: 1240px; padding-top: 2.2rem; padding-bottom: 3rem;
}}
h1, h2, h3, h4 {{ color: {INK}; letter-spacing: -0.02em; }}

/* ---------- sidebar ---------- */
[data-testid="stSidebar"] [data-testid="stSidebarHeader"] {{ padding-top: 1.4rem; padding-bottom: .4rem; }}
[data-testid="stSidebar"] img[data-testid="stSidebarLogo"],
[data-testid="stSidebar"] [data-testid="stSidebarLogo"] {{ height: 34px; max-width: 100%; }}
[data-testid="stSidebarNav"] {{ padding-top: .2rem; }}
[data-testid="stSidebarNavLink"] {{
  border-radius: 10px; margin: 1px 0; padding: .45rem .7rem;
  transition: background .15s ease;
}}
[data-testid="stSidebarNavLink"] span {{ font-weight: 500; color: #334155; }}
[data-testid="stSidebarNavLink"]:hover {{ background: #F3F5FA; }}
[data-testid="stSidebarNavLink"][aria-current="page"] {{ background: {PRIMARY_SOFT}; }}
[data-testid="stSidebarNavLink"][aria-current="page"] span {{ color: {PRIMARY}; font-weight: 600; }}
[data-testid="stSidebarNavSeparator"] {{ display: none; }}
[data-testid="stSidebarUserContent"] {{ padding-top: .4rem; }}

.ns-side-label {{
  font: 600 11px/1 {FONT}; letter-spacing: .08em; text-transform: uppercase;
  color: {SUBTLE}; margin: .6rem 0 .1rem;
}}
[data-testid="stFileUploaderDropzone"] {{
  background: #F8F9FD; border: 1.5px dashed #CBD3E3; border-radius: 12px;
  transition: border-color .15s ease, background .15s ease;
}}
[data-testid="stFileUploaderDropzone"]:hover {{ border-color: {PRIMARY}; background: {PRIMARY_SOFT}; }}

/* ---------- cards (any st.container whose key starts with "card") ---------- */
/* equal-height cards: a card that is the only item in a column fills the column */
[data-testid="stColumn"] > [data-testid="stVerticalBlock"] > [data-testid="stLayoutWrapper"]:only-child:has(> [class*="st-key-card"]) {{
  flex: 1 1 auto; display: flex; flex-direction: column;
}}
[data-testid="stLayoutWrapper"]:only-child > [class*="st-key-card"] {{ flex: 1 1 auto; }}
[class*="st-key-card"] {{
  background: #FFFFFF; border: 1px solid {BORDER}; border-radius: 16px;
  padding: 20px 22px 18px;
  box-shadow: 0 1px 2px rgba(16,24,40,.04), 0 2px 8px -2px rgba(16,24,40,.04);
}}

/* ---------- page header ---------- */
.ns-header {{ display:flex; justify-content:space-between; align-items:flex-end; gap:24px;
  margin: 0 0 22px; flex-wrap: wrap; }}
.ns-eyebrow {{ display:inline-flex; align-items:center; gap:8px; font: 600 12px/1 {FONT};
  letter-spacing:.08em; text-transform:uppercase; color:{PRIMARY}; margin-bottom:10px; }}
.ns-eyebrow::before {{ content:""; width:18px; height:2px; border-radius:2px; background:{PRIMARY}; }}
.ns-title {{ font-family:'Plus Jakarta Sans', {FONT}; font-weight:800; font-size:34px; line-height:1.15;
  letter-spacing:-.03em; color:{INK}; margin:0; }}
.ns-subtitle {{ font: 400 15px/1.55 {FONT}; color:{MUTED}; margin:8px 0 0; max-width: 640px; }}
.ns-chips {{ display:flex; gap:8px; flex-wrap:wrap; }}
.ns-chip {{ display:inline-flex; align-items:center; gap:7px; padding:7px 12px; border-radius:999px;
  background:#FFFFFF; border:1px solid {BORDER}; font: 500 13px/1 {FONT}; color:#334155; white-space:nowrap; }}
.ns-chip svg {{ color:{SUBTLE}; }}
.ns-chip b {{ font-weight:600; color:{INK}; }}

/* ---------- KPI tiles ---------- */
.ns-kpis {{ display:grid; grid-template-columns:repeat(auto-fit, minmax(180px, 1fr)); gap:14px; margin-bottom: 8px; }}
.ns-kpi {{ background:#FFFFFF; border:1px solid {BORDER}; border-radius:16px; padding:18px 18px 16px;
  box-shadow: 0 1px 2px rgba(16,24,40,.04); position:relative; overflow:hidden; }}
.ns-kpi-top {{ display:flex; align-items:center; justify-content:space-between; margin-bottom:14px; }}
.ns-kpi-label {{ font: 500 13px/1.3 {FONT}; color:{MUTED}; }}
.ns-kpi-icon {{ width:32px; height:32px; border-radius:9px; display:grid; place-items:center; }}
.ns-kpi-value {{ font-family:'Plus Jakarta Sans', {FONT}; font-weight:800; font-size:30px; line-height:1;
  letter-spacing:-.03em; color:{INK}; font-variant-numeric: tabular-nums; }}
.ns-kpi-unit {{ font-size:15px; font-weight:700; color:{SUBTLE}; margin-left:4px; letter-spacing:0; }}
.ns-kpi-foot {{ font: 400 12.5px/1.3 {FONT}; color:{SUBTLE}; margin-top:8px; }}

/* ---------- section + card titles ---------- */
.ns-section {{ margin: 30px 0 12px; }}
.ns-section h3 {{ font-family:'Plus Jakarta Sans', {FONT}; font-size:19px; font-weight:700; margin:0;
  color:{INK}; letter-spacing:-.02em; padding:0; }}
.ns-section p {{ font: 400 13.5px/1.5 {FONT}; color:{MUTED}; margin:4px 0 0; }}
.ns-card-title {{ display:flex; align-items:center; gap:10px; margin-bottom:4px; }}
.ns-card-title .dot {{ width:9px; height:9px; border-radius:3px; flex:none; }}
.ns-card-title span {{ font: 600 15px/1.3 {FONT}; color:{INK}; }}
.ns-card-sub {{ font: 400 12.5px/1.45 {FONT}; color:{SUBTLE}; margin:0 0 6px; }}
.ns-muted {{ font: 400 13.5px/1.5 {FONT}; color:{SUBTLE}; padding: 14px 0; }}

/* ---------- key / value list (packet details) ---------- */
.ns-kv {{ margin: 6px 0 0; }}
.ns-kv-row {{ display:flex; justify-content:space-between; gap:16px; padding:10px 0;
  border-top:1px solid #F0F2F7; }}
.ns-kv-row:first-child {{ border-top:none; }}
.ns-kv-k {{ font: 400 13.5px/1.4 {FONT}; color:{MUTED}; flex:none; }}
.ns-kv-v {{ font: 500 13.5px/1.4 'JetBrains Mono', ui-monospace, monospace; color:{INK}; text-align:right;
  word-break: break-word; min-width:0; }}
.ns-kv-v.empty {{ color:#CBD5E1; }}

/* ---------- badges ---------- */
.ns-badge {{ display:inline-flex; align-items:center; gap:6px; padding:4px 10px; border-radius:999px;
  font: 600 12px/1.2 {FONT}; }}

/* ---------- sidebar file card ---------- */
.ns-file {{ border:1px solid {BORDER}; border-radius:12px; padding:12px 12px; background:#FFFFFF;
  display:flex; gap:11px; align-items:center; margin-top:6px; }}
.ns-file-icon {{ width:34px; height:34px; border-radius:9px; background:{PRIMARY_SOFT}; color:{PRIMARY};
  display:grid; place-items:center; flex:none; }}
.ns-file-name {{ font: 600 13.5px/1.3 {FONT}; color:{INK}; word-break: break-all; }}
.ns-file-meta {{ font: 400 12px/1.3 {FONT}; color:{MUTED}; margin-top:3px; }}
.ns-live {{ width:7px; height:7px; border-radius:50%; background:#12B76A; box-shadow:0 0 0 3px #D1FADF;
  margin-left:auto; flex:none; }}

/* ---------- empty state ---------- */
.ns-hero {{ position:relative; overflow:hidden; border-radius:20px; padding:40px 40px 36px;
  background: radial-gradient(1200px 300px at 100% 0%, #E7ECFF 0%, rgba(231,236,255,0) 60%),
              linear-gradient(180deg, #FFFFFF 0%, #FBFCFF 100%);
  border:1px solid {BORDER}; box-shadow: 0 1px 2px rgba(16,24,40,.04); }}
.ns-hero h2 {{ font-family:'Plus Jakarta Sans', {FONT}; font-size:26px; font-weight:800; margin:14px 0 8px;
  letter-spacing:-.03em; color:{INK}; padding:0; }}
.ns-hero p {{ font: 400 15px/1.6 {FONT}; color:{MUTED}; margin:0; max-width:560px; }}
.ns-hero-badge {{ display:inline-flex; align-items:center; gap:8px; padding:6px 12px 6px 8px; border-radius:999px;
  background:{PRIMARY_SOFT}; color:{PRIMARY}; font: 600 12.5px/1 {FONT}; }}
.ns-steps {{ display:grid; grid-template-columns:repeat(auto-fit, minmax(200px,1fr)); gap:14px; margin-top:28px; }}
.ns-step {{ background:#FFFFFF; border:1px solid {BORDER}; border-radius:14px; padding:16px 16px 14px; }}
.ns-step-n {{ width:26px; height:26px; border-radius:8px; background:{INK}; color:#fff; display:grid;
  place-items:center; font: 700 12.5px/1 {FONT}; margin-bottom:12px; }}
.ns-step b {{ display:block; font: 600 14px/1.35 {FONT}; color:{INK}; margin-bottom:4px; }}
.ns-step span {{ font: 400 13px/1.5 {FONT}; color:{MUTED}; }}
.ns-step code {{ font-size:12px; }}
.ns-note {{ display:flex; gap:10px; align-items:flex-start; margin-top:18px; font: 400 13px/1.5 {FONT}; color:{MUTED}; }}
.ns-note svg {{ color:#12B76A; flex:none; margin-top:1px; }}

/* ---------- about page ---------- */
.ns-grid2 {{ display:grid; grid-template-columns:repeat(2, minmax(0,1fr)); gap:14px; }}
@media (max-width: 760px) {{ .ns-grid2 {{ grid-template-columns:1fr; }} }}
.ns-tile {{ background:#FFFFFF; border:1px solid {BORDER}; border-radius:16px; padding:20px 22px; }}
.ns-tile h4 {{ font: 600 15px/1.3 {FONT}; color:{INK}; margin:0 0 10px; padding:0; letter-spacing:0; }}
.ns-tile p, .ns-tile li {{ font: 400 14px/1.6 {FONT}; color:#475569; }}
.ns-tile ol {{ padding-left:18px; margin:0; }}
.ns-tags {{ display:flex; gap:8px; flex-wrap:wrap; }}
.ns-tag {{ padding:6px 11px; border-radius:8px; background:#F3F5FA; border:1px solid #ECEFF5;
  font: 500 13px/1 {FONT}; color:#334155; }}

/* ---------- footer ---------- */
.ns-footer {{ margin-top:40px; padding-top:16px; border-top:1px solid {BORDER}; display:flex;
  justify-content:space-between; flex-wrap:wrap; gap:8px; font: 400 12.5px/1.4 {FONT}; color:{SUBTLE}; }}

/* ---------- native widget polish ---------- */
[data-testid="stExpander"] details {{ border-radius:14px; background:#FFFFFF; border-color:{BORDER}; }}
[data-testid="stDataFrame"] {{ border-radius: 10px; overflow: hidden; }}
[data-testid="stWidgetLabel"] p {{ font-weight:500; color:#334155; }}
hr {{ border-color:{BORDER} !important; }}
</style>
"""


def inject_css() -> None:
    st.html(_CSS)


# ---------------------------------------------------------------------------
# Components
# ---------------------------------------------------------------------------
def page_header(eyebrow: str, title: str, subtitle: str, chips: list[tuple[str, str]] | None = None) -> None:
    chips_html = "".join(f'<span class="ns-chip">{icon(i, 14, SUBTLE)}{c}</span>' for i, c in (chips or []))
    st.html(f"""
    <div class="ns-header">
      <div>
        <div class="ns-eyebrow">{escape(eyebrow)}</div>
        <h1 class="ns-title">{escape(title)}</h1>
        <p class="ns-subtitle">{escape(subtitle)}</p>
      </div>
      <div class="ns-chips">{chips_html}</div>
    </div>""")


def kpi_row(items: list[dict]) -> None:
    """items: dicts with label, value, icon, color, and optional unit / foot."""
    tiles = []
    for it in items:
        color = it.get("color", PRIMARY)
        unit = f'<span class="ns-kpi-unit">{escape(it["unit"])}</span>' if it.get("unit") else ""
        foot = f'<div class="ns-kpi-foot">{escape(it["foot"])}</div>' if it.get("foot") else ""
        tiles.append(f"""
        <div class="ns-kpi">
          <div class="ns-kpi-top">
            <span class="ns-kpi-label">{escape(it["label"])}</span>
            <span class="ns-kpi-icon" style="background:{color}14;color:{color}">{icon(it["icon"], 17, color)}</span>
          </div>
          <div class="ns-kpi-value">{escape(str(it["value"]))}{unit}</div>
          {foot}
        </div>""")
    st.html(f'<div class="ns-kpis">{"".join(tiles)}</div>')


def section(title: str, caption: str = "") -> None:
    cap = f"<p>{escape(caption)}</p>" if caption else ""
    st.html(f'<div class="ns-section"><h3>{escape(title)}</h3>{cap}</div>')


def card_title(title: str, subtitle: str = "", color: str | None = None) -> None:
    dot = f'<span class="dot" style="background:{color}"></span>' if color else ""
    sub = f'<p class="ns-card-sub">{escape(subtitle)}</p>' if subtitle else ""
    st.html(f'<div class="ns-card-title">{dot}<span>{escape(title)}</span></div>{sub}')


def muted(text: str) -> None:
    st.html(f'<div class="ns-muted">{escape(text)}</div>')


def kv_list(rows: list[tuple[str, object]]) -> None:
    """Field / value rows for packet details. Missing values are shown as a dash."""
    html = []
    for k, v in rows:
        missing = v is None or (not isinstance(v, str) and pd.isna(v)) or v == ""
        val = "—" if missing else escape(str(v))
        html.append(f'<div class="ns-kv-row"><span class="ns-kv-k">{escape(k)}</span>'
                    f'<span class="ns-kv-v{" empty" if missing else ""}">{val}</span></div>')
    st.html(f'<div class="ns-kv">{"".join(html)}</div>')


def side_label(text: str) -> None:
    st.sidebar.html(f'<div class="ns-side-label">{escape(text)}</div>')


def file_card(name: str, packets: int, fmt: str, is_sample: bool) -> None:
    badge = (f'<span class="ns-badge" style="background:#ECFDF3;color:#067647;padding:2px 8px;'
             f'font-size:11px;margin-left:6px;vertical-align:1px">Demo</span>') if is_sample else ""
    st.sidebar.html(f"""
    <div class="ns-file">
      <div class="ns-file-icon">{icon("file", 17, PRIMARY)}</div>
      <div style="min-width:0">
        <div class="ns-file-name">{escape(name)}{badge}</div>
        <div class="ns-file-meta">{packets:,} packets · {escape(fmt.upper())}</div>
      </div>
      <span class="ns-live" title="Loaded"></span>
    </div>""")


def empty_state() -> None:
    st.html(f"""
    <div class="ns-hero">
      <span class="ns-hero-badge">{icon("wave", 15, PRIMARY)} Offline packet analysis</span>
      <h2>Load a capture to start exploring</h2>
      <p>Upload a Wireshark <b>.pcap</b> or <b>.pcapng</b> file from the sidebar, or switch on
         <b>Use sample capture</b> to explore a ready-made demo capture straight away.</p>
      <div class="ns-steps">
        <div class="ns-step"><div class="ns-step-n">1</div><b>Capture in Wireshark</b>
          <span>Pick your Wi-Fi or Ethernet interface and start a capture.</span></div>
        <div class="ns-step"><div class="ns-step-n">2</div><b>Generate traffic</b>
          <span>Browse a website, or run <code>ping 8.8.8.8</code> / <code>nslookup example.com</code>.</span></div>
        <div class="ns-step"><div class="ns-step-n">3</div><b>Save the file</b>
          <span>File → Save As… as <i>pcapng</i> or <i>Wireshark/tcpdump – pcap</i>.</span></div>
        <div class="ns-step"><div class="ns-step-n">4</div><b>Upload &amp; analyze</b>
          <span>Drop the file in the sidebar. Everything is processed locally.</span></div>
      </div>
      <div class="ns-note">{icon("shield", 16, "#12B76A")}<span>Only capture traffic on networks you own or are
        authorized to analyze. Uploaded files are deleted right after parsing.</span></div>
    </div>""")


def footer() -> None:
    st.html("""
    <div class="ns-footer">
      <span><b style="color:#475569">TraceNet</b> · Network Traffic Analysis and Packet Analyzer</span>
      <span>Built with Python · Scapy · Pandas · Streamlit</span>
    </div>""")


# ---------------------------------------------------------------------------
# Charts
# ---------------------------------------------------------------------------
_MUTED_CATEGORIES = {"Other / Not Detected", "Not Applicable"}


def bar_chart(data: pd.DataFrame, category: str, color: str = PRIMARY) -> None:
    """Horizontal bar chart with value labels. Catch-all categories are greyed out."""
    data = data.copy()
    data["_color"] = [NEUTRAL_BAR if c in _MUTED_CATEGORIES else color for c in data[category]]
    order = list(data[category])
    base = alt.Chart(data).encode(
        y=alt.Y(f"{category}:N", title=None, sort=order,
                axis=alt.Axis(labelLimit=200, labelPadding=10, ticks=False, domain=False,
                              labelColor="#475569", labelFontSize=12.5, labelFont=FONT)),
        x=alt.X("Packets:Q", title=None, scale=alt.Scale(domainMin=0, nice=True),
                axis=alt.Axis(tickMinStep=1, format="d", grid=True, gridColor="#EEF1F6", gridDash=[3, 3],
                              domain=False, ticks=False, labelColor=SUBTLE, labelFontSize=11,
                              labelFont=FONT, tickCount=4)),
        tooltip=[c for c in data.columns if not c.startswith("_")],
    )
    bars = base.mark_bar(cornerRadiusEnd=6, height={"band": 0.62}).encode(
        color=alt.Color("_color:N", scale=None, legend=None))
    labels = base.mark_text(align="left", dx=6, font=FONT, fontSize=12, fontWeight=600, color=TEXT).encode(
        text=alt.Text("Packets:Q", format=","))
    chart = (bars + labels).properties(height=alt.Step(34)).configure_view(stroke=None) \
        .configure(background="transparent", padding={"left": 0, "right": 24, "top": 4, "bottom": 0})
    st.altair_chart(chart, width="stretch")


def time_chart(data: pd.DataFrame, metric: str, interval: float, color: str = PRIMARY) -> None:
    """Step chart of packets or bytes per time interval (traffic over time)."""
    # Repeat the last interval at its end time so the final step is drawn full width.
    if len(data):
        tail = data.iloc[[-1]].copy()
        tail["Time (s)"] = tail["Time (s)"] + interval
        data = pd.concat([data, tail], ignore_index=True)
    base = alt.Chart(data).encode(
        x=alt.X("Time (s):Q", title=f"Seconds since first packet (bins of {interval:g} s)",
                scale=alt.Scale(domainMin=0, nice=False),
                axis=alt.Axis(grid=False, domain=False, labelColor=SUBTLE, labelFontSize=11,
                              labelFont=FONT, titleColor=MUTED, titleFontSize=11.5, titleFont=FONT,
                              titleFontWeight=500)),
        y=alt.Y(f"{metric}:Q", title=None,
                axis=alt.Axis(format="d" if metric == "Packets" else "~s", tickMinStep=1, grid=True,
                              gridColor="#EEF1F6", gridDash=[3, 3], domain=False, ticks=False,
                              labelColor=SUBTLE, labelFontSize=11, labelFont=FONT, tickCount=4)),
        tooltip=[alt.Tooltip("Time (s):Q", title="From (s)"),
                 alt.Tooltip(f"{metric}:Q", title=metric.capitalize(), format=",")],
    )
    area = base.mark_area(color=color, opacity=0.12, interpolate="step-after")
    line = base.mark_line(color=color, strokeWidth=2, interpolate="step-after")
    chart = (area + line).properties(height=220).configure_view(stroke=None) \
        .configure(background="transparent", padding={"left": 0, "right": 12, "top": 6, "bottom": 0})
    st.altair_chart(chart, width="stretch")

