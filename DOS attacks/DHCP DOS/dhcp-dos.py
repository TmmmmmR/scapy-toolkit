#!/usr/bin/python

# Change log level to suppress annoying IPv6 error
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

#Import Scapi library
from scapy.all import *


def dhcpResponse(pkt):
	pkt.show()


#ip-broadcast = raw_input('Please enter the Broadcasting IP address of the target network : ')

ipbroadcast="10.10.47.255"

filter = "udp and (port 67 or 68)"

#Ethernet layer :
ether = Ether(src=RandMAC(),dst="ff:ff:ff:ff:ff:ff")
#IP layer :
ip    = IP(src="0.0.0.0",dst=ipbroadcast)
#UDP layer
udp   = UDP(sport=68,dport=67)
#BOOTP layer
bootp = BOOTP(chaddr=RandString(12,'0123456789abcdef'))
#Application (DHCP) layer
dhcp  = DHCP(options=[("message-type","discover"),"end"])

# Create and forge the packet
dhcp_discover =  ether/ip/udp/bootp/dhcp

dhcp_req = Ether(src=localm,dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0",dst="255.255.255.255")/UDP(sport=68,dport=67)/BOOTP(chaddr=[mac2str(localm)],xid=localxid)/DHCP(options=[("message-type","request"),("server_id",sip),("requested_addr",myip),("hostname",myhostname),("param_req_list","pad"),"end"])

#Send the packet using send boucle until there is no dhcp response : 
send(dhcp_discover)

# sniff DHCP responses :
sniff(count=0, prn = dhcpResponse, filter=filter, lfilter=lambda(f):f.haslayer(DHCP))


#https://github.com/kamorin/DHCPig/blob/master/pig.py

p_advertise=""

iaid=0xf

trid=None

options=[23,24]

trid=trid or random.randint(0x00,0xffffff)
ethead=v6_build_ether(p_advertise[Ether].dst)
srv_id=DHCP6OptServerId(duid=p_advertise[DHCP6OptServerId].duid)
cli_id=p_advertise[DHCP6OptClientId]
iana=DHCP6OptIA_NA(ianaopts=p_advertise[DHCP6OptIA_NA].ianaopts, iaid=iaid)
dhcp_request=ethead/DHCP6_Request(trid=trid)/cli_id/srv_id/iana/DHCP6OptElapsedTime()/DHCP6OptOptReq( reqopts=options)



SEQUENCE
    ----> DHCP_DISCOVER
    <---- DHCP_OFFER
    ----> DHCP_REQUEST
    <---- DHCP_REPLY (ACK/NACK)

DHCPd snoop detection (DHCPd often checks if IP is in use)
    Check for ARP_Snoops
    Check for ICMP Snoops



return dhcp_request