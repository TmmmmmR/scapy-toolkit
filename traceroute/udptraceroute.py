from scapy.all import *

#dst_ip="8.8.8.8"
#res,unans = sr(IP(dst=dst_ip, ttl=(1,20))/UDP()/DNS(qd=DNSQR(qname="test.com"))

from scapy.all import *
hostname = "8.8.8.8"
for i in range(1, 28):
    pkt = IP(dst=hostname, ttl=i) / UDP(dport=33434)
    # Send the packet and get a reply
    reply = sr1(pkt, verbose=0)
    if reply is None:
        # No reply =(
        break
    elif reply.type == 3:
        # We've reached our destination
        print "Done!", reply.src
        break
    else:
        # We're in the middle somewhere
        print "%d hops away: " % i , reply.src
