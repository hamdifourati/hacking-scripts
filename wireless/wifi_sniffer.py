#!/usr/bin/python

import os
import sys
from time import sleep
from datetime import datetime

from scapy.all import Dot11
from scapy.all import Dot11ProbeResp
from scapy.all import sniff

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

def handle_packet(pkt):
	if not pkt.haslayer(Dot11ProbeResp):
	    try:
	       print "[%s] %s searches for %s " % (str(datetime.now()), pkt[Dot11].addr2, pkt.info)
	    except Exception as e:
	   	   pass

        sleep(0.5)
# start sniffing
print "Sniffing on interface "+iface

sniff(iface=iface, prn=handle_packet)

