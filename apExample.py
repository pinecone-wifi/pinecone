#!/usr/bin/env python3

from pinecone.core.AP import AP

ap = AP("wlan0", 10, "WPA2", "password12345", "TP_LINK")

print("[i] Creating AP...\n"
      "{}\n\n"
      "Press <enter> to stop the AP.\n\n".format(ap))
ap.start()
input()
ap.stop()
