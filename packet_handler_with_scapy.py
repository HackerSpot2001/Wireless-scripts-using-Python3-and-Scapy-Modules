#!/usr/bin/python3
from scapy.all import *

def printPkt(pkt):
    if pkt.haslayer(Dot11):
        print(pkt.summary())


conf.iface = "wlan1mon"
sniff(prn=printPkt)