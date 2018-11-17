import argparse
import signal
from datetime import datetime
from threading import Thread
from time import sleep

from pony.orm import *
from pyric.pyw import Card
from scapy.all import sniff, Packet
from scapy.layers.dot11 import Dot11, Dot11Elt, Dot11ProbeReq, Dot11Beacon, Dot11Auth
from scapy.utils import rdpcap

from pinecone.core.database import Client, ExtendedServiceSet, ProbeReq, BasicServiceSet, Connection
from pinecone.core.main import Pinecone
from pinecone.core.module import BaseModule
from pinecone.utils.interface import set_monitor_mode, check_chset
from pinecone.utils.packet import is_multicast_mac, process_dot11elts, get_dot11_addrs_info, WEP_AUTHN_TYPE_IDS


class Module(BaseModule):
    # ref: https://github.com/aircrack-ng/aircrack-ng/blob/master/src/airodump-ng.h#L141
    CHANNEL_HOPS = {
        "2.4G": (1, 7, 13, 2, 8, 3, 14, 9, 4, 10, 5, 11, 6, 12),
        "5G": (
            36, 38, 40, 42, 44, 46, 48, 50, 52, 54, 56, 58,
            60, 62, 64, 100, 102, 104, 106, 108, 110, 112, 114, 116,
            118, 120, 122, 124, 126, 128, 132, 134, 136, 138, 140, 142,
            144, 149, 151, 153, 155, 157, 159, 161, 165, 169, 173
        ),
        "mix": (
            1, 7, 13, 2, 8, 3, 14, 9, 4, 10, 5, 11, 6,
            12, 36, 38, 40, 42, 44, 46, 48, 50, 52, 54, 56, 58,
            60, 62, 64, 100, 102, 104, 106, 108, 110, 112, 114, 116, 118,
            120, 122, 124, 126, 128, 132, 134, 136, 138, 140, 142, 144, 149,
            151, 153, 155, 157, 159, 161, 165, 169, 173
        )
    }

    META = {
        "id": "discovery/recon",
        "name": "802.11 networks reconnaissance module",
        "author": "Valentín Blanco (https://github.com/valenbg1)",
        "version": "1.1.0",
        "description": "Detects 802.11 APs and clients info and saves it to the recon database for further use.",
        "options": argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter),
        "depends": {}
    }
    META["options"].add_argument(
        "-i", "--iface",
        help="monitor mode capable WLAN interface",
        default="wlan0",
        required=False,
        metavar="INTERFACE"
    )
    META["options"].add_argument(
        "-c", "--channel",
        help="fix interface to specify channel",
        required=False,
        type=int,
        metavar="CHANNEL"
    )
    META["options"].add_argument(
        "-r", "--read",
        dest="input_file",
        help="read a pcap file instead of use interface",
        required=False,
        metavar="INPUT_FILE"
    )
    META["options"].add_argument(
        "-b", "--band",
        help="Scan on specific band. Use 'mix' for all bands",
        default="2.4G",
        choices=CHANNEL_HOPS.keys(),
        metavar="<{}>".format("|".join(CHANNEL_HOPS.keys()))
    )

    def __init__(self):
        self.bssids_cache = None
        self.clients_cache = None
        self.connections_cache = None
        self.iface_current_channel = None
        self.running = False
        self.cmd: Pinecone = None

    def sig_int_handler(self, signal, frame):
        self.running = False
        self.cmd.pfeedback("\n[i] Exiting...\n")

    def sniff(self, iface: str) -> None:
        try:
            sniff(iface=iface, prn=self.handle_packet, store=False, stop_filter=lambda p: not self.running)
        except Exception as e:
            self.cmd.perror("[!] Exception while sniffing: {}".format(e))
            self.running = False

    def channel_hopping(self, interface: Card, band: str) -> None:
        while self.running:
            for channel in self.CHANNEL_HOPS[band]:
                if not self.running: break

                try:
                    self._hop_to_channel(interface, channel)
                    # ref: https://github.com/aircrack-ng/aircrack-ng/blob/master/src/airodump-ng.h#L40
                    sleep(0.250)
                except:
                    pass

    def run(self, args, cmd):
        self.cmd = cmd

        self.clear_caches()
        self.running = True

        if args.input_file is not None:
            self._run_on_pcap(args)
        else:
            self._run_on_interface(args)

    def stop(self, cmd):
        pass

    def clear_caches(self) -> None:
        self.bssids_cache = set()
        self.clients_cache = set()
        self.connections_cache = set()

    @db_session
    def handle_dot11_header(self, packet: Packet) -> None:
        now = datetime.now()
        session = self.cmd.session

        if packet[Dot11].sprintf("%type%") != "Control":
            client_mac = None
            dot11_addrs_info = get_dot11_addrs_info(packet)
            dot11_ds_bits = dot11_addrs_info["ds_bits"]

            if not dot11_ds_bits:  # no to-DS & no from-DS
                bssid = dot11_addrs_info["bssid"]

                if dot11_addrs_info["sa"] != bssid:
                    client_mac = dot11_addrs_info["sa"]
            elif len(dot11_ds_bits) == 1:  # to-DS or from-DS
                bssid = dot11_addrs_info["bssid"]
                client_mac = dot11_addrs_info["sa"] if "to-DS" in dot11_ds_bits else dot11_addrs_info["da"]
            else:  # to-DS & from-DS
                bssid = dot11_addrs_info["ta"]

            if is_multicast_mac(bssid):
                bssid = None

            if client_mac and is_multicast_mac(client_mac):
                client_mac = None

            bss = None
            if bssid:
                try:
                    BasicServiceSet[bssid, session].last_seen = now
                except:
                    bss = BasicServiceSet(bssid=bssid, last_seen=now, session=session)

            if client_mac:
                try:
                    client = Client[client_mac, self.cmd.session]
                except:
                    client = Client(mac=client_mac, session=session)

                if client_mac not in self.clients_cache:
                    self.clients_cache.add(client_mac)
                    self.cmd.pfeedback("[i] Detected client ({})".format(client))

                if bss:
                    try:
                        Connection[client, bss, session].last_seen = now
                    except:
                        Connection(client=client, bss=bss, last_seen=now, session=session)

                    if (client_mac, bssid) not in self.connections_cache:
                        self.connections_cache.add((client_mac, bssid))
                        self.cmd.pfeedback(
                            "[i] Detected connection between client ({}) and BSS (BSSID: {})".format(client, bss.bssid))

    @db_session
    def handle_authn_res(self, packet: Packet) -> None:
        authn_packet = packet[Dot11Auth]

        if authn_packet.sprintf("%status%") == "success" and authn_packet.seqnum in {2, 4}:
            bssid = packet[Dot11].addr3
            bss = BasicServiceSet[bssid, self.cmd.session]

            if bss.encryption_types == "WEP" and authn_packet.algo in WEP_AUTHN_TYPE_IDS:
                bss.authn_types = WEP_AUTHN_TYPE_IDS[authn_packet.algo]

    @db_session
    def handle_probe_req(self, packet: Packet) -> None:
        now = datetime.now()
        ssid = process_dot11elts(packet[Dot11Elt])["ssid"]
        session = self.cmd.session

        if ssid:
            try:
                ess = ExtendedServiceSet[ssid, session]
            except:
                ess = ExtendedServiceSet(ssid=ssid, session=session)

            client_mac = packet[Dot11].addr2
            client = Client[client_mac, session]

            try:
                ProbeReq[client, ess, session].last_seen = now
            except:
                ProbeReq(client=client, ess=ess, last_seen=now, session=session)

            if (client_mac, ssid) not in self.clients_cache:
                self.clients_cache.add((client_mac, ssid))
                self.cmd.pfeedback("[i] Detected client ({}) probing for ESS ({})".format(client, ess))

    @db_session
    def handle_beacon(self, packet: Packet) -> None:
        dot11elts_info = process_dot11elts(packet[Dot11Elt])
        channel = dot11elts_info["channel"]
        encryption_types = ", ".join(dot11elts_info["encryption_types"])

        if channel is None:
            channel = self.iface_current_channel

        if not encryption_types:
            encryption_types = "WEP" if "privacy" in str(packet[Dot11Beacon].cap) else "OPN"

        ssid = dot11elts_info["ssid"]
        ess = None

        if ssid:
            try:
                ess = ExtendedServiceSet[ssid, self.cmd.session]
            except:
                ess = ExtendedServiceSet(ssid=ssid, session=self.cmd.session)

        hides_ssid = ssid == ""
        bssid = packet[Dot11].addr3
        cipher_types = ", ".join(dot11elts_info["cipher_types"])
        authn_types = ", ".join(dot11elts_info["authn_types"])

        bss = BasicServiceSet[bssid, self.cmd.session]
        bss.channel = channel
        bss.encryption_types = encryption_types

        if encryption_types == "WEP":
            bss.cipher_types = "WEP"
        else:
            bss.cipher_types = cipher_types
            bss.authn_types = authn_types

        bss.ess = ess
        bss.hides_ssid = hides_ssid

        if bssid not in self.bssids_cache:
            self.bssids_cache.add(bssid)

            ssid = "\"{}\"".format(ssid) if ssid else "<empty>"
            self.cmd.pfeedback(
                "[i] Detected AP (SSID: {}, BSSID: {}, ch: {}, enc: ({}), cipher: ({}), authn: ({})).".format(
                    ssid,
                    bss.bssid,
                    bss.channel,
                    bss.encryption_types,
                    bss.cipher_types,
                    bss.authn_types)
            )

    @db_session
    def handle_packet(self, packet: Packet) -> None:
        try:
            if packet.haslayer(Dot11):
                self.handle_dot11_header(packet)

                if packet.haslayer(Dot11Beacon):
                    self.handle_beacon(packet)
                elif packet.haslayer(Dot11ProbeReq):
                    self.handle_probe_req(packet)
                elif packet.haslayer(Dot11Auth):
                    self.handle_authn_res(packet)
        except Exception as e:
            self.cmd.perror("[!] Exception while handling packet: {}\n{}".format(e, packet.show(dump=True)))

    def _hop_to_channel(self, interface: Card, channel: int) -> None:
        check_chset(interface, channel)
        self.iface_current_channel = channel

    def _run_on_interface(self, args):
        interface = set_monitor_mode(args.iface)

        join_to = []
        sniff_thread = Thread(target=self.sniff, kwargs={
            "iface": args.iface
        })
        sniff_thread.start()
        join_to.append(sniff_thread)

        if args.channel is None:
            hopping_thread = Thread(target=self.channel_hopping, kwargs={
                "interface": interface,
                "band": args.band
            })
            hopping_thread.start()
            join_to.append(hopping_thread)
        else:
            check_chset(interface, args.channel)

        prev_sig_handler = signal.signal(signal.SIGINT, self.sig_int_handler)

        self.cmd.pfeedback("[i] Starting reconnaissance, press ctrl-c to stop...\n")

        for th in join_to:
            th.join()

        signal.signal(signal.SIGINT, prev_sig_handler)

    def _run_on_pcap(self, args):
        packets = rdpcap(args.input_file)
        for packet in packets:
            self.handle_packet(packet)
