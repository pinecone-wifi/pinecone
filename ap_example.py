#!/usr/bin/env python3

from sys import stdin

from pinecone.core.ap import *

ap = AP(WifiConfig(interface="wlan0", channel=1, encryption="WPA2", password="password12345", essid="TP_LINK"),
        LanConfig(router_ip="192.168.0.1", netmask="255.255.255.0", out_iface="eth0", dhcp_start_addr="192.168.0.50",
                  dhcp_end_addr="192.168.0.150", dhcp_lease_time="12h"),
        {"www.facebook.com": "127.0.0.1", "www.google.com": "127.0.0.1"})

print("AP config:\n"
      "{}\n".format(ap))

while True:
    print("\nCommand (start|stop|exit): ", end="")
    cmd = input()

    if cmd == "start":
        if ap.start():
            print("\nAP started correctly!\n")
        else:
            print("\nERROR: AP didn't start correctly!\n")
    elif cmd == "stop":
        print("\nStopping AP...\n")
        ap.stop()
    elif cmd == "exit":
        break
