#!/usr/bin/env python3

import signal
from argparse import ArgumentParser
from datetime import datetime
from sys import stderr

from pony.orm import *
from pyric import pyw
from scapy.layers.dot11 import Dot11, Dot11Elt, Packet, Dot11ProbeReq, Dot11Beacon, sniff

from pinecone.core.database import Client, ExtendedServiceSet, ProbeReq, BasicServiceSet
from pinecone.core.utils import IfaceUtils, ScapyUtils

bssids_cache = set()
clients_cache = set()
iface_current_channel = None


@db_session
def handle_probe_req(packet: Packet):
    now = datetime.now()
    client_mac = packet[Dot11].addr2

    try:
        client = Client[client_mac]
    except:
        client = Client(mac=client_mac)

    ssid = ScapyUtils.process_dot11elts(packet[Dot11Elt])["ssid"]
    ess = None

    if ssid:
        try:
            ess = ExtendedServiceSet[ssid]
        except:
            ess = ExtendedServiceSet(ssid=ssid)

        try:
            ProbeReq[client, ess].last_seen = now
        except:
            ProbeReq(client=client, ess=ess, last_seen=now)

    if (client_mac, ssid) not in clients_cache:
        clients_cache.add((client_mac, ssid))
        print("[i] Detected client ({}){}.".format(client,
                                                   " probing for ESS ({})".format(ess) if ess is not None else ""))


@db_session
def handle_beacon(packet: Packet):
    now = datetime.now()

    dot11elts_info = ScapyUtils.process_dot11elts(packet[Dot11Elt])
    ssid = dot11elts_info["ssid"]
    channel = dot11elts_info["channel"]
    encryption_types = ", ".join(dot11elts_info["encryption_types"])
    hides_ssid = not ssid
    ess = None
    bssid = packet[Dot11].addr3

    if channel is None:
        channel = iface_current_channel

    if not encryption_types:
        capabilities = packet.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}")
        encryption_types = "WEP" if "privacy" in capabilities else "OPN"

    if ssid:
        try:
            ess = ExtendedServiceSet[ssid]
        except:
            ess = ExtendedServiceSet(ssid=ssid)

    try:
        bss = BasicServiceSet[bssid]
        bss.channel = channel
        bss.encryption_types = encryption_types
        bss.cipher_types = ""
        bss.authn_types = ""
        bss.last_seen = now
        bss.ess = ess
        bss.hides_ssid = hides_ssid
    except:
        BasicServiceSet(bssid=bssid, channel=channel, encryption_types=encryption_types, cipher_types="",
                        authn_types="", last_seen=now, ess=ess, hides_ssid=hides_ssid)

    if bssid not in bssids_cache:
        bssids_cache.add(bssid)

        ssid = "\"{}\"".format(ssid) if ssid else "<empty>"
        print("[i] Detected AP: SSID: {}, BSSID: {}, ch: {}, enc: ({}), cipher: ({}), authn: ({}).".format(ssid, bssid,
                                                                                                           channel,
                                                                                                           encryption_types,
                                                                                                           "", ""))


def handle_packet(packet: Packet):
    try:
        if packet.haslayer(Dot11ProbeReq):
            handle_probe_req(packet)
        elif packet.haslayer(Dot11Beacon):
            handle_beacon(packet)
    except Exception as e:
        print("\n[!] Exception while handling packet: {}\n".format(e), file=stderr)


if __name__ == "__main__":
    args_parser = ArgumentParser()
    args_parser.add_argument("-i", "--iface", help="wlan interface", default="wlan0", type=str)
    args = args_parser.parse_args()

    chann_hops = (1, 6, 11, 2, 7, 12, 3, 8, 13, 4, 9, 5, 10)

    running = True


    def sig_exit_handler(signal, frame):
        global running
        running = False

        print("\n[i] Exiting...\n")


    signal.signal(signal.SIGTERM, sig_exit_handler)
    signal.signal(signal.SIGINT, sig_exit_handler)

    interface = IfaceUtils.set_monitor_mode(args.iface)

    while running:
        for channel in chann_hops:
            pyw.chset(interface, channel)
            iface_current_channel = channel
            sniff(iface=args.iface, prn=handle_packet, timeout=3, store=False)

            if not running: break
