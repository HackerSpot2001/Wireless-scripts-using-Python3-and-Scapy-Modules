#!/usr/bin/python3
from scapy.all import *

brdmac = 'ff:ff:ff:ff:ff:ff'
mymac = 'aa:bb:cc:dd:ee:ff'
targetMac = str(input("Enter the Target MAC: "))

with open('new.txt','r') as f:
    for ssid in f.readlines():
        pkt = RadioTap() / Dot11(type=0,subtype=5,addr1=mymac,addr2=targetMac,addr3=targetMac) / Dot11ProbeReq() / Dot11Elt(ID=0,info="Cloacked!") / Dot11Elt(ID=1,info='\x02\x04\x0b\x16') / Dot11Elt(ID=3,info='\x08')
        sendp(pkt,iface='wlan1mon',count=10,inter= .3)