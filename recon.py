#!/usr/bin/env python3

import signal
from argparse import ArgumentParser
from datetime import datetime
from sys import stderr

from pony.orm import *
from pyric import pyw
from scapy.layers.dot11 import Dot11, Dot11Elt, Packet, Dot11ProbeReq, Dot11Beacon, sniff

from pinecone.core.database import Client, ExtendedServiceSet, ProbeReq, BasicServiceSet
from pinecone.core.utils import IfaceUtils

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

    elt_field = packet[Dot11Elt]
    ssid = None

    while isinstance(elt_field, Dot11Elt):
        if elt_field.ID == 0 and elt_field.len and elt_field.len > 0:
            try:
                ssid = elt_field.info.decode()
            except:
                pass

        elt_field = elt_field.payload

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
    channel = None
    elt_field = packet[Dot11Elt]
    encryption_types = set()
    ssid = None

    while isinstance(elt_field, Dot11Elt):
        if elt_field.ID == 0 and elt_field.len and elt_field.len > 0:
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
        elif elt_field.ID == 221 and elt_field.info.startswith(b"\x00\x50\xf2\x01\x01\x00"):
            encryption_types.add("WPA")

        elt_field = elt_field.payload

    if channel is None:
        channel = iface_current_channel

    if not encryption_types:
        capabilities = packet.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}").split('+')
        encryption_types.add("WEP" if "privacy" in capabilities else "OPN")

    encryption_type = encryption_types.pop()
    ess = None
    hides_ssid = False

    if ssid:
        try:
            ess = ExtendedServiceSet[ssid]
        except:
            ess = ExtendedServiceSet(ssid=ssid)
    else:
        hides_ssid = True

    bssid = packet[Dot11].addr3

    try:
        bss = BasicServiceSet[bssid]
        bss.channel = channel
        bss.encryption = encryption_type
        bss.last_seen = now
        bss.ess = ess
        bss.hides_ssid = hides_ssid
    except:
        bss = BasicServiceSet(bssid=bssid, channel=channel, encryption=encryption_type, last_seen=now,
                              ess=ess, hides_ssid=hides_ssid)

    if bssid not in bssids_cache:
        bssids_cache.add(bssid)
        print("[i] Detected AP: ({}).".format(bss))


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
