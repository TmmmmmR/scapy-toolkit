#!/usr/bin/python

# Change log level to suppress annoying IPv6 error
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

#Import Scapy library
from scapy.all import *

def callback(pkt):
    if pkt.haslayer(DNS):
        pkt[DNS].dport = 10000
        send(pkt)

sniff(filter="host 192.168.0.5", prn=callback, store=0, iface="wlan0")