#!/usr/bin/env python3

import signal
from argparse import ArgumentParser

from pyric import pyw
from scapy.layers.dot11 import *

from pinecone.core.utils import IfaceUtils
from pinecone.model import *

bssid_cache = set()


def handle_probe_req(packet: Packet):
    client_mac = packet[Dot11].addr2
    elt_field = packet[Dot11Elt]
    essid = None

    while isinstance(elt_field, Dot11Elt):
        if elt_field.ID == 0 and elt_field.len > 0:
            essid = elt_field.info.decode()

        elt_field = elt_field.payload

    print("[i] Detected client {} probing".format(client_mac), end="")

    if essid is not None:
        print(" for '{}' ESSID".format(essid), end="")

    print(".")


@db_session
def handle_beacon(packet: Packet):
    bssid = packet[Dot11].addr3

    if bssid in bssid_cache:
        return

    bssid_cache.add(bssid)

    p = packet[Dot11Elt]
    cap = packet.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}").split('+')
    ssid, channel = None, None
    crypto = set()
    while isinstance(p, Dot11Elt):
        if p.ID == 0:
            ssid = p.info.decode()
        elif p.ID == 3:
            channel = ord(p.info)
        elif p.ID == 48:
            crypto.add("WPA2")
        elif p.ID == 221 and p.info.startswith(b"\x00P\xf2\x01\x01\x00"):
            crypto.add("WPA")
        p = p.payload
    if not crypto:
        if "privacy" in cap:
            crypto.add("WEP")
        else:
            crypto.add("OPN")

    enc = crypto.pop()
    try:
        ess = ExtendedServiceSet(ssid=ssid)
        commit()
    except:
        pass

    try:
        # TODO: fix multiple encryptions APs
        ess = ExtendedServiceSet[ssid]
        BasicServiceSet(bssid=bssid, channel=channel, enc=enc, ess=ess)
        commit()
    except:
        pass

    print("[i] Detected AP: [ch:{}] {} [{}], {}".format(channel, ssid, bssid, enc))


def handle_packet(packet: Packet):
    if packet.haslayer(Dot11ProbeReq):
        handle_probe_req(packet)
    elif packet.haslayer(Dot11Beacon):
        handle_beacon(packet)


if __name__ == "__main__":
    args_parser = ArgumentParser()
    args_parser.add_argument("-i", "--iface", help="wlan interface", default="wlan0", type=str)
    args = args_parser.parse_args()

    chann_hops = (1, 6, 11, 2, 7, 12, 3, 8, 13, 4, 9, 5, 10)

    running = True


    def sig_exit_handler(signal, frame):
        global running
        running = False

        print("[i] Exiting...")


    signal.signal(signal.SIGTERM, sig_exit_handler)
    signal.signal(signal.SIGINT, sig_exit_handler)

    interface = IfaceUtils.set_monitor_mode(args.iface)

    while running:
        try:
            for channel in chann_hops:
                pyw.chset(interface, channel)
                sniff(iface=args.iface, prn=handle_packet, timeout=3, store=False)

                if not running: break
        except KeyboardInterrupt:
            pass
