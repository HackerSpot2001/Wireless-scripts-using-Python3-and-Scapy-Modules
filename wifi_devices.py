#!/usr/bin/python3
from scapy.all import *

def wifiDevices(pkt):
    if pkt.haslayer(Dot11):
        dot11_layer = pkt.getlayer(Dot11)
        mac = dot11_layer.addr2
        if (mac) and (mac not in Devices):
            Devices.add(mac)
            print("[+] {} MAC: {}, {}".format(len(Devices),mac,dot11_layer.payload.name))

    


if __name__ == "__main__":
    Devices = set()
    conf.iface = 'wlan1mon'
    print("[*] Finding MAC Addresses near You................")
    sniff(prn=wifiDevices)