"""
Traffic statistics for TraceNet.

All functions take the packet DataFrame from packet_parser and return values
computed from the real packets in it. Nothing here is hardcoded.
"""

from __future__ import annotations

from typing import Any

import pandas as pd

from netscope.protocol_analyzer import HTTP_METHODS


def total_packets(df: pd.DataFrame) -> int:
    return int(len(df))


def total_bytes(df: pd.DataFrame) -> int:
    """Sum of captured packet lengths, in bytes."""
    return int(df["length"].sum()) if len(df) else 0


def format_bytes(num_bytes: int) -> str:
    """Human readable size, e.g. 1536 -> '1.50 KB'."""
    size = float(num_bytes)
    for unit in ["bytes", "KB", "MB", "GB"]:
        if size < 1024 or unit == "GB":
            return f"{int(size)} bytes" if unit == "bytes" else f"{size:.2f} {unit}"
        size /= 1024
    return f"{size:.2f} GB"


def unique_source_ips(df: pd.DataFrame) -> int:
    return int(df["src_ip"].dropna().nunique())


def unique_destination_ips(df: pd.DataFrame) -> int:
    return int(df["dst_ip"].dropna().nunique())


def dns_packet_count(df: pd.DataFrame) -> int:
    return int((df["application_protocol"] == "DNS").sum())


def top_ips(df: pd.DataFrame, column: str, n: int = 5) -> pd.DataFrame:
    """Top-n IP addresses in 'src_ip' or 'dst_ip' by packet count."""
    counts = df[column].dropna().value_counts().head(n)
    return pd.DataFrame({"IP Address": counts.index, "Packets": counts.values})


def capture_duration(df: pd.DataFrame) -> float:
    """Seconds between the first and the last packet."""
    ts = df["timestamp"].dropna()
    return float(ts.max() - ts.min()) if len(ts) else 0.0


def summary(df: pd.DataFrame) -> dict[str, Any]:
    """All overview statistics in one dictionary."""
    return {
        "total_packets": total_packets(df),
        "total_bytes": total_bytes(df),
        "unique_src_ips": unique_source_ips(df),
        "unique_dst_ips": unique_destination_ips(df),
        "dns_packets": dns_packet_count(df),
        "duration": capture_duration(df),
    }


# ---------------------------------------------------------------------------
# TCP analysis
# ---------------------------------------------------------------------------
def tcp_flag_counts(df: pd.DataFrame) -> pd.DataFrame:
    """Count TCP packets by flag combination (e.g. 'SYN', 'SYN, ACK')."""
    tcp = df[df["transport_protocol"] == "TCP"]
    counts = tcp["tcp_flags"].fillna("(none)").replace("", "(none)").value_counts()
    return pd.DataFrame({"TCP Flags": counts.index, "Packets": counts.values})


def find_tcp_handshakes(df: pd.DataFrame) -> pd.DataFrame:
    """Detect completed TCP three-way handshakes.

    A handshake between client C and server S is:
        1. C -> S  SYN        seq = x
        2. S -> C  SYN, ACK   seq = y, ack = x + 1
        3. C -> S  ACK        ack = y + 1   (no SYN flag)
    We match the three packets using IP addresses, ports and the
    sequence / acknowledgement numbers.

    When timestamps are available the handshake round-trip time (RTT) is
    added: SYN -> SYN-ACK is the time for one round trip from the client to
    the server and back, as seen by a capture taken on the client.
    """
    tcp = df[df["transport_protocol"] == "TCP"].sort_values("packet_no")
    has_time = "timestamp" in tcp.columns
    pending_syn: dict[tuple, dict] = {}     # key: (cip, cport, sip, sport)
    pending_synack: dict[tuple, dict] = {}
    handshakes = []

    for row in tcp.itertuples(index=False):
        flags = _flag_set(row.tcp_flags)
        key = (row.src_ip, row.src_port, row.dst_ip, row.dst_port)
        reverse = (row.dst_ip, row.dst_port, row.src_ip, row.src_port)
        t = row.timestamp if has_time else None

        if "SYN" in flags and "ACK" not in flags:
            pending_syn[key] = {"syn_no": row.packet_no, "seq": row.tcp_seq, "t1": t}
        elif flags >= {"SYN", "ACK"}:
            syn = pending_syn.get(reverse)
            if syn and row.tcp_ack == (syn["seq"] + 1) % SEQ_MOD:
                pending_synack[reverse] = {**syn, "synack_no": row.packet_no,
                                           "seq2": row.tcp_seq, "t2": t}
        elif "ACK" in flags:
            sa = pending_synack.get(key)
            if sa and row.tcp_ack == (sa["seq2"] + 1) % SEQ_MOD:
                hs = {
                    "Client": f"{row.src_ip}:{row.src_port}",
                    "Server": f"{row.dst_ip}:{row.dst_port}",
                    "SYN (packet)": sa["syn_no"],
                    "SYN-ACK (packet)": sa["synack_no"],
                    "ACK (packet)": row.packet_no,
                }
                if has_time:
                    hs["Handshake RTT (ms)"] = _ms(sa["t2"] - sa["t1"])
                handshakes.append(hs)
                del pending_synack[key]
                pending_syn.pop(key, None)

    columns = ["Client", "Server", "SYN (packet)", "SYN-ACK (packet)", "ACK (packet)"]
    if has_time:
        columns.append("Handshake RTT (ms)")
    return pd.DataFrame(handshakes, columns=columns)


SEQ_MOD = 2**32  # TCP sequence numbers wrap around at 2^32


def _flag_set(flags: Any) -> set[str]:
    return set(str(flags or "").split(", ")) - {""}


def _ms(seconds: float) -> float:
    return round(float(seconds) * 1000, 3)


def _segment_length(row) -> int:
    """Sequence space used by a segment: payload bytes, plus 1 for SYN and for FIN."""
    flags = _flag_set(row.tcp_flags)
    payload = 0 if pd.isna(row.tcp_payload_len) else int(row.tcp_payload_len)
    return payload + ("SYN" in flags) + ("FIN" in flags)


def tcp_retransmissions(df: pd.DataFrame) -> pd.DataFrame:
    """Find retransmitted TCP segments.

    A segment is a retransmission when the same sender already sent a
    segment with the same sequence number that used sequence space (data,
    SYN or FIN) in the same direction of the same connection. Pure ACKs use
    no sequence space and are never counted.
    """
    tcp = df[df["transport_protocol"] == "TCP"].sort_values("packet_no")
    first_sent: dict[tuple, tuple] = {}   # (direction, seq) -> (packet number, time)
    rows = []
    for row in tcp.itertuples(index=False):
        length = _segment_length(row)
        if length == 0 or pd.isna(row.tcp_seq):
            continue
        direction = (row.src_ip, row.src_port, row.dst_ip, row.dst_port)
        key = (direction, int(row.tcp_seq))
        if key in first_sent:
            original, t_first = first_sent[key]
            rows.append({
                "Packet": row.packet_no,
                "Connection": f"{row.src_ip}:{row.src_port} → {row.dst_ip}:{row.dst_port}",
                "Flags": row.tcp_flags,
                "Sequence number": int(row.tcp_seq),
                "Payload (bytes)": 0 if pd.isna(row.tcp_payload_len) else int(row.tcp_payload_len),
                "Original packet": original,
                "Delay (ms)": _ms(row.timestamp - t_first),
            })
        else:
            first_sent[key] = (row.packet_no, row.timestamp)
    return pd.DataFrame(rows, columns=["Packet", "Connection", "Flags", "Sequence number",
                                       "Payload (bytes)", "Original packet", "Delay (ms)"])


RTT_COLUMNS = ["Sender", "Receiver", "Segments sent", "Retransmissions", "RTT samples",
               "Min RTT (ms)", "Avg RTT (ms)", "Max RTT (ms)"]


def tcp_rtt(df: pd.DataFrame) -> pd.DataFrame:
    """Estimate the TCP round-trip time, separately for each direction.

    For every segment that uses sequence space (data, SYN or FIN), one RTT
    sample is the time until the first packet from the receiver whose
    acknowledgement number covers it (ack >= seq + length).

    Segments that were sent more than once are skipped (Karn's algorithm),
    because it is impossible to know which copy the ACK answers.

    Each direction gets its own row because the meaning depends on where the
    capture was taken: for a capture on the client, client -> server rows
    measure the real network round trip, while server -> client rows only
    measure how quickly the client itself replied.
    """
    tcp = df[df["transport_protocol"] == "TCP"].sort_values("packet_no")
    sent_count: dict[tuple, int] = {}   # (direction, seq) -> copies sent
    for row in tcp.itertuples(index=False):
        if _segment_length(row) and not pd.isna(row.tcp_seq):
            key = ((row.src_ip, row.src_port, row.dst_ip, row.dst_port), int(row.tcp_seq))
            sent_count[key] = sent_count.get(key, 0) + 1

    pending: dict[tuple, list] = {}     # direction -> [(end_seq, send_time)]
    stats: dict[tuple, dict] = {}       # direction -> counters and samples
    for row in tcp.itertuples(index=False):
        direction = (row.src_ip, row.src_port, row.dst_ip, row.dst_port)
        reverse = (row.dst_ip, row.dst_port, row.src_ip, row.src_port)
        # 1) Does this packet acknowledge segments sent the other way?
        if "ACK" in _flag_set(row.tcp_flags) and not pd.isna(row.tcp_ack) and pending.get(reverse):
            waiting = []
            for end, t_sent in pending[reverse]:
                if (int(row.tcp_ack) - end) % SEQ_MOD < 2**31:   # ack >= end, allowing wrap-around
                    stats[reverse]["samples"].append(row.timestamp - t_sent)
                else:
                    waiting.append((end, t_sent))
            pending[reverse] = waiting
        # 2) Is this a segment that needs to be acknowledged?
        length = _segment_length(row)
        if length and not pd.isna(row.tcp_seq):
            st = stats.setdefault(direction, {"sent": 0, "retrans": 0, "samples": [], "seen": set()})
            seq = int(row.tcp_seq)
            if seq in st["seen"]:
                st["retrans"] += 1
            else:
                st["sent"] += 1
                st["seen"].add(seq)
                if sent_count[(direction, seq)] == 1:   # Karn: only segments sent once
                    pending.setdefault(direction, []).append(((seq + length) % SEQ_MOD, row.timestamp))

    rows = []
    for (sip, sport, dip, dport), st in stats.items():
        samples = st["samples"]
        rows.append({
            "Sender": f"{sip}:{sport}",
            "Receiver": f"{dip}:{dport}",
            "Segments sent": st["sent"],
            "Retransmissions": st["retrans"],
            "RTT samples": len(samples),
            "Min RTT (ms)": _ms(min(samples)) if samples else None,
            "Avg RTT (ms)": _ms(sum(samples) / len(samples)) if samples else None,
            "Max RTT (ms)": _ms(max(samples)) if samples else None,
        })
    return pd.DataFrame(rows, columns=RTT_COLUMNS)


# ---------------------------------------------------------------------------
# Conversations and traffic over time
# ---------------------------------------------------------------------------
def conversations(df: pd.DataFrame) -> pd.DataFrame:
    """Packets and bytes exchanged between each pair of IP addresses.

    Like Wireshark's Statistics > Conversations (IPv4/IPv6 tab): A is the
    address that sent the first packet of the pair, B the other one. ARP is
    left out because it is not carried in an IP packet.
    """
    ip = df[df["network_protocol"].isin(["IPv4", "IPv6"])].sort_values("packet_no")
    convs: dict[frozenset, dict] = {}
    for row in ip.itertuples(index=False):
        pair = frozenset((row.src_ip, row.dst_ip))
        c = convs.setdefault(pair, {"A": row.src_ip, "B": row.dst_ip, "ab_p": 0, "ab_b": 0,
                                    "ba_p": 0, "ba_b": 0, "start": row.timestamp,
                                    "end": row.timestamp, "protocols": set()})
        if row.src_ip == c["A"]:
            c["ab_p"] += 1
            c["ab_b"] += int(row.length)
        else:
            c["ba_p"] += 1
            c["ba_b"] += int(row.length)
        c["end"] = row.timestamp
        c["protocols"].add(row.protocol)
    t0 = df["timestamp"].min() if len(df) else 0.0
    rows = [{
        "Address A": c["A"],
        "Address B": c["B"],
        "Packets": c["ab_p"] + c["ba_p"],
        "Bytes": c["ab_b"] + c["ba_b"],
        "Packets A→B": c["ab_p"],
        "Bytes A→B": c["ab_b"],
        "Packets B→A": c["ba_p"],
        "Bytes B→A": c["ba_b"],
        "Start (s)": round(float(c["start"] - t0), 3),
        "Duration (s)": round(float(c["end"] - c["start"]), 3),
        "Protocols": ", ".join(sorted(c["protocols"])),
    } for c in convs.values()]
    columns = ["Address A", "Address B", "Packets", "Bytes", "Packets A→B", "Bytes A→B",
               "Packets B→A", "Bytes B→A", "Start (s)", "Duration (s)", "Protocols"]
    out = pd.DataFrame(rows, columns=columns)
    return out.sort_values(["Packets", "Bytes"], ascending=False, ignore_index=True)


_NICE_INTERVALS = [0.001, 0.002, 0.005, 0.01, 0.02, 0.05, 0.1, 0.2, 0.5,
                   1, 2, 5, 10, 15, 30, 60, 120, 300, 600, 900, 1800, 3600]


def choose_interval(duration: float, target_bins: int = 40) -> float:
    """Pick a round bin width so the chart has about target_bins bars."""
    for step in _NICE_INTERVALS:
        if duration / step <= target_bins:
            return step
    return _NICE_INTERVALS[-1]


def traffic_over_time(df: pd.DataFrame, interval: float | None = None) -> pd.DataFrame:
    """Packets and bytes in each time interval since the first packet.

    Empty intervals are kept (with 0) so gaps in the traffic are visible.
    """
    columns = ["Time (s)", "Packets", "Bytes"]
    t = df["relative_time"].dropna() if "relative_time" in df.columns else pd.Series(dtype=float)
    if t.empty:
        return pd.DataFrame(columns=columns)
    if interval is None:
        interval = choose_interval(float(t.max()))
    bins = (df.loc[t.index, "relative_time"] // interval).astype(int)
    grouped = df.loc[t.index].groupby(bins).agg(Packets=("packet_no", "size"), Bytes=("length", "sum"))
    full = grouped.reindex(range(int(bins.max()) + 1), fill_value=0)
    full.insert(0, "Time (s)", [round(i * interval, 6) for i in full.index])
    return full.reset_index(drop=True)[columns]


# ---------------------------------------------------------------------------
# HTTP and TLS summaries
# ---------------------------------------------------------------------------
def http_requests(df: pd.DataFrame) -> pd.DataFrame:
    """HTTP requests found in the capture (method, path and Host)."""
    http = df[df["application_protocol"] == "HTTP"]
    method = http["http_info"].fillna("").str.split(" ").str[0]
    req = http[method.isin(HTTP_METHODS)]
    replies = http[~method.isin(HTTP_METHODS)]
    rows = []
    for r in req.itertuples(index=False):
        # The reply is the first HTTP status line sent back on the same connection.
        back = replies[(replies["packet_no"] > r.packet_no) & (replies["src_ip"] == r.dst_ip)
                       & (replies["src_port"] == r.dst_port) & (replies["dst_port"] == r.src_port)]
        rows.append({
            "Packet": r.packet_no,
            "Client": r.src_ip,
            "Host": r.http_host or r.dst_ip,
            "Request": r.http_info,
            "Response": back.iloc[0]["http_info"] if len(back) else "",
        })
    return pd.DataFrame(rows, columns=["Packet", "Client", "Host", "Request", "Response"])


def tls_server_names(df: pd.DataFrame, n: int = 10) -> pd.DataFrame:
    """Server names (SNI) requested in TLS Client Hello messages."""
    hello = df[(df["application_protocol"] == "TLS") & df["tls_sni"].notna()]
    counts = hello["tls_sni"].value_counts().head(n)
    return pd.DataFrame({"Server name (SNI)": counts.index, "Client Hellos": counts.values})


# ---------------------------------------------------------------------------
# ICMP and DNS analysis
# ---------------------------------------------------------------------------
def icmp_type_counts(df: pd.DataFrame) -> pd.DataFrame:
    icmp = df[df["transport_protocol"].isin(["ICMP", "ICMPv6"])]
    if icmp.empty:
        return pd.DataFrame(columns=["Protocol", "Message Type", "Packets"])
    counts = icmp.groupby(["transport_protocol", "icmp_info"]).size().reset_index(name="Packets")
    counts.columns = ["Protocol", "Message Type", "Packets"]
    return counts.sort_values("Packets", ascending=False, ignore_index=True)


def top_dns_queries(df: pd.DataFrame, n: int = 10) -> pd.DataFrame:
    """Most frequently queried domain names (DNS queries only, not responses)."""
    q = df[(df["application_protocol"] == "DNS") & (df["dns_direction"] == "Query")]
    counts = q["dns_query"].dropna().value_counts().head(n)
    return pd.DataFrame({"Domain": counts.index, "Queries": counts.values})
