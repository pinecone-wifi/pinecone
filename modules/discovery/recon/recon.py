import itertools
import signal
from datetime import datetime
from queue import Queue, Empty
from threading import Thread
from time import sleep

from pony.orm import *
from pyric.pyw import Card
from scapy.all import sniff, Packet
from scapy.layers.dot11 import Dot11, Dot11FCS, Dot11Elt, Dot11ProbeReq, Dot11Beacon, Dot11Auth, RadioTap
from scapy.utils import PcapReader, PcapWriter

from pinecone.core.database import Client, ExtendedServiceSet, ProbeReq, BasicServiceSet, Connection
from pinecone.core.main import Pinecone
from pinecone.core.module import BaseModule
from pinecone.utils.interface import set_monitor_mode, check_chset
from pinecone.utils.packet import is_multicast_mac, process_dot11elts, get_dot11_addrs_info, WEP_AUTHN_TYPE_IDS
from pinecone.core.options import Option, OptionDict


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
        "options": OptionDict(),
        "depends": {}
    }
    META["options"].add(Option("INTERFACES", ["wlan0"], True, "monitor mode capable WLAN interfaces.", is_list=True))
    # TODO: fix unique channel.
    META["options"].add(Option("CHANNEL", description="fix interface to specific channel.", opt_type=int))
    # TODO: fix handle packet queue.
    META["options"].add(Option("INPUT_FILE", description="read a pcap file instead of using an interface."))
    META["options"].add(Option("OUTPUT_FILE", description="write a pcap file with processed packages."))
    META["options"].add(Option("BAND", "2.4G", True, "scan on specific band. Use 'mix' for all bands", choices=CHANNEL_HOPS.keys()))

    def __init__(self):
        self.bssids_cache = None
        self.clients_cache = None
        self.connections_cache = None
        self.iface_current_channel = None
        self.running = False
        self.cmd: Pinecone = None
        self.in_pkcs_queue = Queue()
        self.out_writer: PcapWriter = None

    def sig_int_handler(self, signal, frame):
        self.running = False
        self.cmd.pfeedback("\n[i] Exiting...\n")

    def sniff(self, iface: str) -> None:
        try:
            sniff(iface=iface, prn=self.handle_packet, store=False, stop_filter=lambda p: not self.running)
        except Exception as e:
            self.cmd.perror("[!] Exception while sniffing: {}".format(e))
            self.running = False

    def channel_hopping(self, interfaces: Card, band: str) -> None:
        channel_iterator = itertools.cycle(self.CHANNEL_HOPS[band])
        while self.running:
            for interface in interfaces:
                if not self.running:
                    break

                try:
                    self._hop_to_channel(interface, next(channel_iterator))
                except:
                    pass

            # ref: https://github.com/aircrack-ng/aircrack-ng/blob/master/src/airodump-ng.h#L40
            sleep(0.250)

    def run(self, opts, cmd):
        opts = opts.get_opts_namespace()
        self.cmd = cmd

        self.clear_caches()
        self.running = True

        if opts.input_file is not None:
            self._run_on_pcap(opts)
        else:
            self._run_on_interface(opts)

    def stop(self, cmd):
        pass

    def clear_caches(self) -> None:
        self.bssids_cache = set()
        self.clients_cache = set()
        self.connections_cache = set()

    @db_session
    def handle_dot11_header(self, packet: Packet) -> None:
        now = datetime.now()
        radiotap_pkg = packet[RadioTap]
        dot11_pkg = packet[Dot11]

        if dot11_pkg.sprintf("%type%") != "Control":
            client_mac = None
            dot11_addrs_info = get_dot11_addrs_info(dot11_pkg)
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
                    bss = BasicServiceSet[bssid]
                    bss.last_seen = now
                except:
                    bss = BasicServiceSet(bssid=bssid, last_seen=now)

                if dot11_addrs_info["ta"] != dot11_addrs_info["bssid"]:
                    # Transmission Address match bssid, so packet came from an AP
                    # get signal strength and update DB if needed
                    current_dbm = radiotap_pkg.dBm_AntSignal
                    if current_dbm and (not bss.max_dbm_power or current_dbm > bss.max_dbm_power):
                        bss.max_dbm_power = current_dbm
                        # TODO: Get GPS fix and update max power position

            if client_mac:
                try:
                    client = Client[client_mac]
                except:
                    client = Client(mac=client_mac)

                if client_mac not in self.clients_cache:
                    self.clients_cache.add(client_mac)
                    self.cmd.pfeedback("[i] Detected client ({})".format(client))

                if bss:
                    try:
                        Connection[client, bss].last_seen = now
                    except:
                        Connection(client=client, bss=bss, last_seen=now)

                    if (client_mac, bssid) not in self.connections_cache:
                        self.connections_cache.add((client_mac, bssid))
                        self.cmd.pfeedback(
                            "[i] Detected connection between client ({}) and BSS (BSSID: {})".format(client, bss.bssid))

    @db_session
    def handle_authn_res(self, packet: Packet) -> None:
        authn_packet = packet[Dot11Auth]

        if authn_packet.sprintf("%status%") == "success" and authn_packet.seqnum in {2, 4}:
            bssid = packet[Dot11].addr3
            bss = BasicServiceSet[bssid]

            if bss.encryption_types == "WEP" and authn_packet.algo in WEP_AUTHN_TYPE_IDS:
                bss.authn_types = WEP_AUTHN_TYPE_IDS[authn_packet.algo]

    @db_session
    def handle_probe_req(self, packet: Packet) -> None:
        now = datetime.now()
        ssid = process_dot11elts(packet[Dot11Elt])["ssid"]

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
                ess = ExtendedServiceSet[ssid]
            except:
                ess = ExtendedServiceSet(ssid=ssid)

        hides_ssid = ssid == ""
        bssid = packet.addr3
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

        if bssid not in self.bssids_cache:
            self.bssids_cache.add(bssid)

            ssid = "\"{}\"".format(ssid) if ssid else "<empty>"
            current_dbm = packet[RadioTap].dBm_AntSignal
            self.cmd.pfeedback(
                "[i] Detected AP (SSID: {}, BSSID: {}, ch: {}, enc: ({}), cipher: ({}), authn: ({}), dBm: {}).".format(
                    ssid,
                    bss.bssid,
                    bss.channel,
                    bss.encryption_types,
                    bss.cipher_types,
                    bss.authn_types,
                    current_dbm)
            )

    @db_session
    def handle_packet_queue(self) -> None:
        while self.running:
            try:
                packet = self.in_pkcs_queue.get(timeout=1)
            except Empty:
                # Allow re evaluation of self.running for controlled cleanup
                continue

            if self.out_writer:
                self.out_writer.write(packet)

            try:
                if packet.haslayer(Dot11) or packet.haslayer(Dot11FCS):
                    self.handle_dot11_header(packet)

                    if packet.haslayer(Dot11Beacon):
                        self.handle_beacon(packet)
                    elif packet.haslayer(Dot11ProbeReq):
                        self.handle_probe_req(packet)
                    elif packet.haslayer(Dot11Auth):
                        self.handle_authn_res(packet)
            except Exception as e:
                self.cmd.perror("[!] Exception while handling packet: {}\n{}".format(e, packet.show(dump=True)))

    def handle_packet(self, packet: Packet) -> None:
        try:
            if packet.haslayer(Dot11) or packet.haslayer(Dot11FCS):
                self.in_pkcs_queue.put(packet)
        except Exception as e:
            self.cmd.perror("[!] Exception while handling packet: {}\n{}".format(e, packet.show(dump=True)))

    def _hop_to_channel(self, interface: Card, channel: int) -> None:
        check_chset(interface, channel)
        self.iface_current_channel = channel

    def _run_on_interface(self, opts):
        interfaces = []
        join_to = []

        if opts.output_file:
            self.out_writer = PcapWriter(opts.output_file)

        handle_queue_thread = Thread(target=self.handle_packet_queue)
        handle_queue_thread.start()

        join_to.append(handle_queue_thread)

        for iface in opts.interfaces:
            interfaces.append(set_monitor_mode(iface))

            sniff_thread = Thread(target=self.sniff, kwargs={
                "iface": iface
            })
            sniff_thread.start()

            join_to.append(sniff_thread)

        if opts.channel is None:
            hopping_thread = Thread(target=self.channel_hopping, kwargs={
                "interfaces": interfaces,
                "band": opts.band
            })
            hopping_thread.start()
            join_to.append(hopping_thread)
        else:
            for interface in interfaces:
                check_chset(interface, opts.channel)

        prev_sig_handler = signal.signal(signal.SIGINT, self.sig_int_handler)

        self.cmd.pfeedback("[i] Starting reconnaissance, press ctrl-c to stop...\n")

        for th in join_to:
            th.join()

        if self.out_writer:
            self.out_writer.close()

        signal.signal(signal.SIGINT, prev_sig_handler)

    def _run_on_pcap(self, opts):
        reader = PcapReader(opts.input_file)

        try:
            while True:
                self.handle_packet(reader.read_packet())
        except EOFError:
            pass

        reader.close()
