#!/usr/bin/python3
from scapy.all import *

def ssid_finder_using_scapy(pkt):
    if pkt.haslayer(Dot11Beacon):
        # beacon_layer = pkt.getlayer(Dot11Beacon)
        if (pkt.info) and (pkt.info not in ssids):
            print("[+] {}. SSID: {}".format(len(ssids),(pkt.info).decode()))
            ssids.add(pkt.info)

if __name__ == "__main__":
    conf.iface = 'wlan1mon'
    ssids = set()
    sniff(prn=ssid_finder_using_scapy)