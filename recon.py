#!/usr/bin/env python3

import signal
from argparse import ArgumentParser
from datetime import datetime
from sys import stderr

from pony.orm import *
from pyric import pyw
from scapy.layers.dot11 import sniff, Packet, Dot11, Dot11Elt, Dot11ProbeReq, Dot11Beacon, Dot11Auth

from pinecone.core.database import Client, ExtendedServiceSet, ProbeReq, BasicServiceSet, Connection
from pinecone.core.utils import IfaceUtils, ScapyUtils

bssids_cache = set()
clients_cache = set()
connections_cache = set()
iface_current_channel = None


@db_session
def handle_dot11_header(packet: Packet):
    now = datetime.now()
    dot11_packet = packet[Dot11]

    if dot11_packet.sprintf("%type%") != "Control":
        dot11_ds_bits = {flag for flag in str(dot11_packet.FCfield).split("+") if flag in {"to-DS", "from-DS"}}
        client_mac = None

        if not dot11_ds_bits:
            bssid = dot11_packet.addr3

            if dot11_packet.addr2 != bssid:
                client_mac = dot11_packet.addr2
        elif len(dot11_ds_bits) == 1:
            if "to-DS" in dot11_ds_bits:
                bssid = dot11_packet.addr1
                client_mac = dot11_packet.addr2
            else:  # from-DS
                bssid = dot11_packet.addr2
                client_mac = dot11_packet.addr1
        else:  # to-DS & from-DS
            bssid = dot11_packet.addr2

        if ScapyUtils.is_multicast_mac(bssid):
            bssid = None

        if client_mac and ScapyUtils.is_multicast_mac(client_mac):
            client_mac = None

        bss = None
        if bssid:
            try:
                bss = BasicServiceSet[bssid]
                bss.last_seen = now
            except:
                bss = BasicServiceSet(bssid=bssid, last_seen=now)

        if client_mac:
            try:
                client = Client[client_mac]
            except:
                client = Client(mac=client_mac)

            if client_mac not in clients_cache:
                clients_cache.add(client_mac)
                print("[i] Detected client ({})".format(client))

            if bss:
                try:
                    Connection[client, bss].last_seen = now
                except:
                    Connection(client=client, bss=bss, last_seen=now)

                if (client_mac, bssid) not in connections_cache:
                    connections_cache.add((client_mac, bssid))
                    print("[i] Detected connection between client ({}) and BSS (BSSID: {})".format(client, bssid))


@db_session
def handle_authn_res(packet: Packet):
    authn_packet = packet[Dot11Auth]

    if authn_packet.sprintf("%status%") == "success" and authn_packet.seqnum in {2, 4}:
        bssid = packet[Dot11].addr3
        bss = BasicServiceSet[bssid]

        if bss.encryption_types == "WEP" and authn_packet.algo in ScapyUtils.wep_authn_type_ids:
            bss.authn_types = ScapyUtils.wep_authn_type_ids[authn_packet.algo]


@db_session
def handle_probe_req(packet: Packet):
    now = datetime.now()
    ssid = ScapyUtils.process_dot11elts(packet[Dot11Elt])["ssid"]

    if ssid:
        try:
            ess = ExtendedServiceSet[ssid]
        except:
            ess = ExtendedServiceSet(ssid=ssid)

        client_mac = packet[Dot11].addr2
        client = Client[client_mac]

        try:
            ProbeReq[client, ess].last_seen = now
        except:
            ProbeReq(client=client, ess=ess, last_seen=now)

        if (client_mac, ssid) not in clients_cache:
            clients_cache.add((client_mac, ssid))
            print("[i] Detected client ({}) probing for ESS ({})".format(client, ess))


@db_session
def handle_beacon(packet: Packet):
    dot11elts_info = ScapyUtils.process_dot11elts(packet[Dot11Elt])
    channel = dot11elts_info["channel"]
    encryption_types = ", ".join(dot11elts_info["encryption_types"])

    if channel is None:
        channel = iface_current_channel

    if not encryption_types:
        encryption_types = "WEP" if "privacy" in str(packet[Dot11Beacon].cap) else "OPN"

    ssid = dot11elts_info["ssid"]
    ess = None

    if ssid:
        try:
            ess = ExtendedServiceSet[ssid]
        except:
            ess = ExtendedServiceSet(ssid=ssid)

    hides_ssid = ssid == ""
    bssid = packet[Dot11].addr3
    cipher_types = ", ".join(dot11elts_info["cipher_types"])
    authn_types = ", ".join(dot11elts_info["authn_types"])

    bss = BasicServiceSet[bssid]
    bss.channel = channel
    bss.encryption_types = encryption_types

    if encryption_types == "WEP":
        bss.cipher_types = "WEP"
    else:
        bss.cipher_types = cipher_types
        bss.authn_types = authn_types

    bss.ess = ess
    bss.hides_ssid = hides_ssid

    if bssid not in bssids_cache:
        bssids_cache.add(bssid)

        ssid = "\"{}\"".format(ssid) if ssid else "<empty>"
        print("[i] Detected AP (SSID: {}, BSSID: {}, ch: {}, enc: ({}), cipher: ({}), authn: ({})).".format(ssid, bssid,
                                                                                                            channel,
                                                                                                            encryption_types,
                                                                                                            cipher_types,
                                                                                                            authn_types))


def handle_packet(packet: Packet):
    try:
        if packet.haslayer(Dot11):
            handle_dot11_header(packet)

            if packet.haslayer(Dot11Beacon):
                handle_beacon(packet)
            elif packet.haslayer(Dot11ProbeReq):
                handle_probe_req(packet)
            elif packet.haslayer(Dot11Auth):
                handle_authn_res(packet)
    except Exception as e:
        print("\n[!] Exception while handling packet: {}\n{}".format(e, packet.show(dump=True)), file=stderr)


if __name__ == "__main__":
    args_parser = ArgumentParser()
    args_parser.add_argument("-i", "--iface", help="wlan interface", default="wlan0", type=str)
    args = args_parser.parse_args()

    chann_hops = (1, 6, 11, 14, 2, 7, 12, 3, 8, 13, 4, 9, 5, 10)

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
