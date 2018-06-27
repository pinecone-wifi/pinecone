#!/usr/bin/env python3

from pinecone.core.ap import *

wifi_config = WifiConfig("wlan0", 10, "WPA2", "password12345", "TP_LINK")
dhcp_config = DhcpConfig("192.168.0.50", "192.168.0.150", "12h")

ap = AP(wifi_config, dhcp_config)

print("[i] Creating AP...\n"
      "{}\n\n"
      "Press <enter> to stop the AP.\n\n".format(ap))
ap.start()
input()
ap.stop()
