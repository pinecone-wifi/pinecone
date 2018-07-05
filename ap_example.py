#!/usr/bin/env python3

from pinecone.core.ap import *

ap = AP(
    wifi_config=WifiConfig(interface="wlan0", channel=10, encryption="WPA2", password="password12345", essid="TP_LINK"),
    lan_config=LanConfig(router_ip="192.168.0.1", netmask="255.255.255.0", out_iface="eth0",
                         dhcp_start_addr="192.168.0.50", dhcp_end_addr="192.168.0.150", dhcp_lease_time="12h"),
    dns_custom_hosts={"www.facebook.com": "127.0.0.1", "www.google.com": "127.0.0.1"})

print("[i] Starting AP...\n"
      "AP config:\n"
      "{}\n\n"
      "Press <enter> to stop the AP.\n\n".format(ap))

ap.start()
input()
ap.stop()
