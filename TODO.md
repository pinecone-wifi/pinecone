- **TODO:**
    * Comments in source code.
    * Network graph report module (@rsrdesarrollo).
    ---------
    * Custom hosts in dnsmasq module.
    * Include last_seen field in clients in DB.
    * Include first_seen fields in DB.
    * Split script/attack/wpa_handshake functionality in another module.
    * Test WEP authn methods.
    * hostapd-wpe log file.
    * Better autocompleting in CLI commands.

- **DOING:**

- **ON HOLD:**
    * Recon specific WEP enc types (requires parsing of 802.11 data frames).

- **DONE:**
    * Save AP beacon in PCAP file in script/attack/wpa_handshake module.
    * Improve attack/deauth module.
    * check_chset().
    * "Select BSS" function in database.py.
    * Save command history.
    * Previous deauth attack in AP script ("free Wi-Fi").
    * MAC ACL in daemon/hostapd-wpe.
    * Empty SSIDs with non zero length in recon module.
    * Handle exceptions when sniffing in recon module.
    * Rogue WPA enterprise support in AP script (hostapd-wpe).
    * Module template.
    * Recon continuous leave/enter promiscuous mode problem.
    * DB to JSON module.
    * Improve meta and args in all modules.
    * WPA handshake stealing script.
    * AP script.
    * dnsmasq module.
    * hostapd module.
    * Improve DB writing performance in recon.
    * Init interactive CLI.
    * Module base class.
    * Deauth module.
    * Recon module.
    * Recon WEP authn types (requires parsing of 802.11 auth res).
    * Hides SSID attr.
    * Check iface channel vs 802.11 IE channel.
    * Recon 802.11 header.
    * Recon WPA / WPA2 cipher and authn types.
    * Check SSID str / channel int in ELT field.
    * Move model module to core module.
    * Util to set an interface to monitor mode.
