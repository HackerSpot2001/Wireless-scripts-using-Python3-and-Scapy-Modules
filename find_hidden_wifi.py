#!/usr/bin/python3
from scapy.all import *

def hidden_wifi(pkt):
    if pkt.haslayer(Dot11Beacon):
        if not pkt.info:
            if pkt.addr3 not in hidden_ap:
                hidden_ap.add(pkt.addr3)
                print("HIDDEN SSID Network: {}".format(pkt.addr3))
    
    elif (pkt.haslayer(Dot11ProbeResp)) and (pkt.addr3 in hidden_ap):
        print("HIDDEN SSID UNCOVERED ",pkt.info,pkt.addr3)


if __name__ == "__main__":
    conf.iface = "wlan1mon"
    hidden_ap = set()
    sniff(prn=hidden_wifi)