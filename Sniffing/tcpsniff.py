from scapy.all import *
from prettytable import *

def dhcp(p):
	p.sprintf("%TCP.flags%")

pkts = sniff(filter="tcp",count=3,prn=dhcp)
pkts.nsummary(lfilter = lambda (r): r.sprintf("%TCP.flags%") == "A")

