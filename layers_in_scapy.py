#!/usr/bin/python3
from scapy.all import *

def printDot11(pkt):
    if pkt.haslayer(Dot11Elt):
        ssid = pkt.getlayer(Dot11Elt).info
        ssid = ssid.decode()
        if (ssid not in ssids) :
            if ssid != ' ':
                print("SSID: {}".format(ssid))
                ssids.append(ssid)



if __name__ == "__main__":
    ssids = []
    conf.iface = 'wlan1mon'
    sniff(prn=printDot11)