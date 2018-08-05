import argparse
from ipaddress import ip_network
from subprocess import run

import iptc
from pathlib2 import Path
from pyric import pyw

from pinecone.core.script import BaseScript
from pinecone.utils.template import to_args_str


class Module(BaseScript):
    META = {
        "id": "scripts/infrastructure/ap",
        "name": "AP script",
        "author": "Valentín Blanco (https://github.com/valenbg1/)",
        "version": "1.0.0",
        "description": "Runs an AP with DNS and DHCP capabilities.",
        "options": argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter),
        "depends": {"daemon/dnsmasq", "daemon/hostapd"}
    }
    META["options"].add_argument("-i", "--iface", help="AP mode capable WLAN interface", default="wlan0")
    META["options"].add_argument("-c", "--channel", help="AP channel", default=1, type=int)
    META["options"].add_argument("-e", "--encryption", help="AP encryption", default="WPA2")
    META["options"].add_argument("-p", "--password", help="AP password", default="password12345")
    META["options"].add_argument("-s", "--ssid", help="AP SSID", default="PINECONEWIFI")
    META["options"].add_argument("-o", "--out-iface",
                                 help="output interface (no-LAN packets will be redirected there).", default="eth0")
    META["options"].add_argument("--router-ip", help="router LAN IP", default="192.168.0.1")
    META["options"].add_argument("--netmask", help="network netmask", default="255.255.255.0")
    META["options"].add_argument("--dhcp-start-addr", help="DHCP start address", default="192.168.0.50")
    META["options"].add_argument("--dhcp-end-addr", help="DHCP end address", default="192.168.0.150")
    META["options"].add_argument("--dhcp-lease-time", help="DHCP lease time", default="12h")

    START_SCRIPT_TEMPLATE_PATH = Path(Path(__file__).parent, "start_ap_template").resolve()  # type: Path
    START_SCRIPT_FILENAME = "start_ap_script"

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
