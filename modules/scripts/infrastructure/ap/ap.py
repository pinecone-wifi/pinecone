import argparse
from ipaddress import ip_network
from subprocess import run
from typing import Dict, Any

import iptc
from pathlib2 import Path
from pyric import pyw

from pinecone.core.main import Pinecone
from pinecone.core.script import BaseScript
from pinecone.utils.template import to_args_str


class Module(BaseScript):
    META = {
        "id": "modules/scripts/infrastructure/ap",
        "name": "",
        "author": "",
        "version": "",
        "description": "",
        "options": argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter),
        "depends": {"modules/daemon/dnsmasq", "modules/daemon/hostapd"}
    }  # type: Dict[str, Any]
    META["options"].add_argument("-i", "--iface", help="AP mode capable WLAN interface.", default="wlan0", type=str)
    META["options"].add_argument("-c", "--channel", default=1, type=int)
    META["options"].add_argument("-e", "--encryption", help="AP encryption type.", default="WPA2", type=str)
    META["options"].add_argument("-p", "--password", default="password12345", type=str)
    META["options"].add_argument("-s", "--ssid", default="PINECONEWIFI", type=str)
    META["options"].add_argument("-o", "--out-iface",
                                 help="Output interface (no-LAN packets will be redirected there).", default="eth0",
                                 type=str)
    META["options"].add_argument("--router-ip", help="router IP.", default="192.168.0.1", type=str)
    META["options"].add_argument("--netmask", help="Network netmask.", default="255.255.255.0", type=str)
    META["options"].add_argument("--dhcp-start-addr", help="DHCP start address.", default="192.168.0.50", type=str)
    META["options"].add_argument("--dhcp-end-addr", help="DHCP end address.", default="192.168.0.150", type=str)
    META["options"].add_argument("--dhcp-lease-time", help="DHCP lease time.", default="12h", type=str)

    START_SCRIPT_TEMPLATE_PATH = Path(Path(__file__).parent, "start_ap_template").resolve()  # type: Path
    START_SCRIPT_FILENAME = "start_ap_script"  # type: str

    STOP_SCRIPT_PATH = Path(Path(__file__).parent, "stop_ap_script").resolve()  # type: Path

    def __init__(self):
        super().__init__()

    def run(self, args, cmd):
        script_args = argparse.Namespace()
        script_args.hostapd_args = to_args_str({
            "iface": args.iface,
            "channel": args.channel,
            "encryption": args.encryption,
            "password": args.password,
            "ssid": args.ssid
        })
        script_args.dnsmasq_args = to_args_str({
            "start-addr": args.dhcp_start_addr,
            "end-addr": args.dhcp_end_addr,
            "lease-time": args.dhcp_lease_time,
        })
        super().run(script_args, cmd)

        pyw.ifaddrset(pyw.getcard(args.iface), args.router_ip, args.netmask)

        run(["sysctl", "-w", "net.ipv4.ip_forward=1"])

        iptc.Table(iptc.Table.NAT).flush()
        nat_rule = iptc.Rule()
        nat_rule.src = str(ip_network("{}/{}".format(args.router_ip, args.netmask), strict=False))
        nat_rule.out_interface = args.out_iface
        nat_rule.target = nat_rule.create_target("MASQUERADE")
        iptc.Chain(iptc.Table(iptc.Table.NAT), "POSTROUTING").append_rule(nat_rule)

    def stop(self, cmd):
        super().stop(cmd)

        run(["sysctl", "-w", "net.ipv4.ip_forward=0"])

        iptc.Table(iptc.Table.NAT).flush()
