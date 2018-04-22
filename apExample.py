from pinecone.core.AP import AP

ap = AP("wlan0", 10, "WPA2", "password12345", "TP_LINK")
ap.start()