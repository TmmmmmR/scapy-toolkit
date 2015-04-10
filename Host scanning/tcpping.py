from scapy.all import *
from prettytable import *

# Define end host and TCP port range
target = "google.com"
portRange = [21,22,23,25,80,110,443,513,3389,6000]
results = PrettyTable(["Host", "Port", "State"]) 

# Send TCP packets with SYnN flag
for dstPort in portRange:

	resp = sr1(IP(dst=target)/TCP(dport=[21,22,23,25,80,110,443,513,3389,6000],flags="S"))	

	if (resp.haslayer(TCP)):
	    if(resp.getlayer(TCP).flags == 0x12):
	        results.add_row([resp[IP].src, dstPort, "open"])
	        #print host + ":" + str(dstPort) + " is open."
	    elif (resp.getlayer(TCP).flags == 0x14):
	        results.add_row([resp[IP].src, dstPort, "closed"])

print results
#>>> ans,unans=sr( IP(dst="192.168.1.*")/TCP(dport=[21,22,23,25,80,110,443,513,3389,6000],flags="S") )
#>>> ans.summary( lambda(s,r) : r.sprintf("%IP.src% is alive") )
