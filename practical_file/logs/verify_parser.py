import sys, os
sys.path.insert(0, os.getcwd())
from netscope.packet_parser import parse_capture, CaptureFileError
from netscope import protocol_analyzer as pa, traffic_statistics as ts, filters
D="NetScope_Demo_Data/"
df, info = parse_capture("sample_data/sample_capture.pcap")
print(info); s=ts.summary(df); print(s, ts.format_bytes(s['total_bytes']))
print(ts.top_ips(df,'src_ip').head(2).to_string(), ts.top_ips(df,'dst_ip').head(2).to_string())
for k,v in pa.layer_distributions(df).items(): print(k); print(v.to_string())
print(ts.tcp_flag_counts(df).to_string()); print(ts.find_tcp_handshakes(df).to_string())
print(ts.icmp_type_counts(df).to_string()); print(ts.top_dns_queries(df).to_string())
cols=['packet_no','src_mac','dst_mac','src_ip','dst_ip','network_protocol','transport_protocol','application_protocol','src_port','dst_port','length','tcp_flags','tcp_seq','tcp_ack','icmp_type','icmp_code','icmp_info','arp_operation','dns_query','dns_query_type','dns_direction']
import pandas as pd; pd.set_option('display.width',400); pd.set_option('display.max_columns',40)
print(df[df.packet_no.isin([1,2,3,4,11,12,13,14,15,59,60,61,62,65,68,69,72])][cols].to_string())
for args,lab in [((['DNS'],'192.168.1.10','8.8.8.8'),'dns'),((['DNS','ARP'],'',''),'dns+arp'),((['ARP'],'',''),'arp'),((['ICMPv6'],'',''),'icmpv6'),(([],'198.51.100.254',''),'nomatch'),((['TCP'],'',''),'tcp')]:
    v=filters.apply_filters(df,*args); print(lab, len(v), list(v.packet_no)[:12])
df2,i2=parse_capture(D+"sample_capture.pcapng"); print('pcapng',i2, ts.summary(df2), (df2[['timestamp','length']].values==df[['timestamp','length']].values).all())
df3,i3=parse_capture(D+"sample_capture.pcap"); print('kit pcap',i3, ts.summary(df3)==s)
for f in ["invalid_demo.pcap","no_packets.pcap","truncated_demo.pcap"]:
    try: d,i=parse_capture(D+f); print(f,i, ts.summary(d)); print(d.tail(1)[cols].to_string())
    except CaptureFileError as e: print(f,'ERROR:',e)
