from scapy.all import *

dst_ip="8.8.8.8"

ans,unans=sr(IP(dst=dst_ip,ttl=(1,10))/TCP(dport=53,flags="S"))
ans.summary( lambda(s,r) : r.sprintf("%IP.src%\t{ICMP:%ICMP.type%}\t{TCP:%TCP.flags%}"))
