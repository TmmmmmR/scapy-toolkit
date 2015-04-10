from scapy.all import *

dst = "example.com"
ans,unans=traceroute("4.2.2.1",l4=UDP(sport=RandShort())/DNS(qd=DNSQR(qname=dst)))
