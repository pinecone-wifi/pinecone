#!/usr/bin/env python3

import signal
from argparse import ArgumentParser
from datetime import datetime

from pony.orm import *
from pyric import pyw
from scapy.layers.dot11 import *

from pinecone.core.utils import IfaceUtils
from pinecone.model import *

bssid_cache = set()
client_cache = set()


@db_session
def handle_probe_req(packet: Packet):
    now = datetime.now()
    client_mac = packet[Dot11].addr2

    try:
        client = Client[client_mac]
    except:
        client = Client(mac=client_mac)

    elt_field = packet[Dot11Elt]
    ssid = None

    while isinstance(elt_field, Dot11Elt):
        if elt_field.ID == 0 and elt_field.len is not None and elt_field.len > 0:
            try:
                ssid = elt_field.info.decode()
            except:
                pass

        elt_field = elt_field.payload

    if ssid is not None:
        try:
            ess = ExtendedServiceSet[ssid]
        except:
            ess = ExtendedServiceSet(ssid=ssid)

        try:
            ProbeReq[client, ess].last_seen = now
        except:
            ProbeReq(client=client, ess=ess, last_seen=now)

        print("[i] Detected client {} probing for '{}' ESSID.".format(client_mac, ssid))
    elif client_mac not in client_cache:
        client_cache.add(client_mac)
        print("[i] Detected client {}.".format(client_mac))


@db_session
def handle_beacon(packet: Packet):
    now = datetime.now()
    bssid = packet[Dot11].addr3
    elt_field = packet[Dot11Elt]
    capability_list = packet.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}").split('+')
    ssid = None
    channel = None
    encryption_types = set()

    while isinstance(elt_field, Dot11Elt):
        if elt_field.ID == 0 and elt_field.len is not None and elt_field.len > 0:
            try:
                ssid = elt_field.info.decode()
            except:
                pass
        elif elt_field.ID == 3:
            try:
                channel = ord(elt_field.info)
            except:
                pass
        elif elt_field.ID == 48:
            encryption_types.add("WPA2")
        elif elt_field.ID == 221 and elt_field.info.startswith(b"\x00P\xf2\x01\x01\x00"):
            encryption_types.add("WPA")

        elt_field = elt_field.payload

    if not encryption_types:
        encryption_types.add("WEP" if "privacy" in capability_list else "OPN")

    encryption_type = encryption_types.pop()

    ess = None

    if ssid is not None:
        try:
            ess = ExtendedServiceSet[ssid]
        except:
            ess = ExtendedServiceSet(ssid=ssid)

    try:
        bss = BasicServiceSet[bssid]

        if channel is not None:
            bss.channel = channel

        bss.encryption = encryption_type
        bss.last_seen = now
        bss.ess = ess
    except:
        if channel is not None:
            BasicServiceSet(bssid=bssid, channel=channel, encryption=encryption_type, last_seen=now,
                            ess=ess)

    if bssid not in bssid_cache:
        bssid_cache.add(bssid)
        print(
            "[i] Detected AP: [ch:{}] [SSID: {}] [BSSID: {}] [encryption: {}]".format(channel, ssid, bssid,
                                                                                      encryption_type))


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
