#!/usr/bin/env python3

from pinecone.core.ap import *

ap = AP(WifiConfig(channel=10, essid="TP_LINK"))

print("[i] Starting AP...\n"
      "AP config:\n"
      "{}\n\n"
      "Press <enter> to stop the AP.\n\n".format(ap))
ap.start()
input()
ap.stop()
