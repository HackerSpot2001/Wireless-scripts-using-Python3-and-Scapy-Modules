#!/usr/bin/python3
from scapy.all import *
import os 
import sqlite3

def find_clients(pkt):
    if pkt.haslayer(Dot11ProbeReq):
        if len(pkt.info) >0:
            testcase = pkt.addr2+" ---> " + (pkt.info).decode()
            if testcase not in clientProbes:
                clientProbes.add(testcase)
                # print("[+] New Probe Found: "+testcase)
                print("\n------------ Clients Probe Table ---------------")
                counter = 1
                for Probe in clientProbes:
                    # os.system("clear")
                    client,ssid = Probe.split('--->')
                    print(counter,client,ssid)



if __name__ == "__main__":
    conf.iface = "wlan1mon"
    conn = sqlite3.connect('probes.db')
    cursor = conn.cursor()
    clientProbes = set()
    sniff(prn=find_clients)
    conn.close