#!/usr/bin/python

import os
import sys

from scapy.all import Dot11Beacon
from scapy.all import Dot11ProbeReq
from scapy.all import Dot11ProbeResp
from scapy.all import sniff
from scapy.all import Raw
# set interface
iface = "wlan0"
if len(sys.argv)>1:
    iface = sys.argv[1]

#set monitor mode
#TODO: imllement exceptions (permissions, device busy..)
try:
	os.system("iwconfig "+iface+" mode monitor")
except Exception as e:
	exit()
#only handle beacons packets, probe req/res

def dump_packet(pkt):
	if not pkt.haslayer(Dot11Beacon) and \
	   not pkt.haslayer(Dot11ProbeReq) and \
	   not pkt.haslayer(Dot11ProbeResp):

	   print pkt.summary()

	   if pkt.haslayer(Raw):
	      print hexdump(pkt.load)
	   print "\n"

#keep sniffing
while True:
	for channel in {11, 1}:
		try:
			os.system("iwconfig "+iface+" channel "+str(channel))
		except Exception as e:
			exit()

        print "Sniffing on channel "+str(channel)

        sniff(iface=iface, prn=dump_packet, count=10, timeout=3,store=0)

