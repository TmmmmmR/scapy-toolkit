#!/usr/bin/python

# Change log level to suppress annoying IPv6 error
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

#Import Scapi library
from scapy.all import *

filter = "port 53"

from scapy.all import *
def callback(pkt):
    if pkt.haslayer(TCP):
    	# nsummary function ...
        print pkt.nsummary()
        # show funtion ...
        print pkt.show()
        # equivalent to print pkt.getlayer(TCP)
        print pkt[TCP] 
        #  

sniff(filter=filter, lfilter=lambda(f):f.haslayer(DNS), prn=callback, store=0, iface="wlan0")