#!/usr/bin/python3
from scapy.all import *
brdmac = 'ff:ff:ff:ff:ff:ff'
mymac = 'aa:bb:cc:dd:ee:ff'


with open('new.txt','r') as f:
    for ssid in f.readlines():
        pkt = RadioTap() / Dot11(type=0,subtype=4,addr1=brdmac,addr2=mymac,addr3=brdmac) / Dot11ProbeReq() / Dot11Elt(ID=0,info=ssid.strip()) / Dot11Elt(ID=1,info='\x02\x04\x0b\x16') / Dot11Elt(ID=3,info='\x08')
        sendp(pkt,iface='wlan1mon',count=10,inter= .3)