from scapy.all import *
from prettytable import *


def dns_print(pkt):	
    if pkt.haslayer(DNSQR): # DNS question record
    	global results
    	results.add_row([pkt[DNS].qd.qname, pkt[IP].src, pkt[IP].dst])

results = PrettyTable(["DNS query", "Source", "Destination"])
sniff(filter='udp port 53', iface='wlan0', count=20, prn=dns_print)
print results

