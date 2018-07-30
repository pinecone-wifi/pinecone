import typing
from subprocess import run

import iptc
from pyric import pyw


class AP:
    def __init__(self, wifi_config: WifiConfig = None, lan_config: LanConfig = None,
                 dns_custom_hosts: typing.Dict[str, str] = None):
        if wifi_config is None:
            wifi_config = WifiConfig()

        if lan_config is None:
            lan_config = LanConfig()

        if dns_custom_hosts is None:
            dns_custom_hosts = dict()

        self.wifi_config = wifi_config
        self.lan_config = lan_config
        self.dns_custom_hosts = dns_custom_hosts

        self._hostapd_handler = _HostapdHandler(self.wifi_config)
        self._dnsmasq_handler = _DnsmasqHandler(self.lan_config, self.dns_custom_hosts)

    def __str__(self):
        return "Wifi config:\n" \
               "{}\n\n" \
               "LAN config:\n" \
               "{}".format(self.wifi_config, self.lan_config)

    def is_running(self):
        return self._hostapd_handler.is_running() and self._dnsmasq_handler.is_running()

    def reload_dns_custom_hosts(self):
        self._dnsmasq_handler.reload_custom_hosts()

    def stop(self):
        self._hostapd_handler.stop()
        self._dnsmasq_handler.stop()

        run(["sysctl", "-w", "net.ipv4.ip_forward=0"])

        iptc.Table(iptc.Table.NAT).flush()

    def start(self) -> bool:
        self._hostapd_handler.run()
        self._dnsmasq_handler.run()

        pyw.ifaddrset(pyw.getcard(self.wifi_config.interface), self.lan_config.router_ip, self.lan_config.netmask)

        run(["sysctl", "-w", "net.ipv4.ip_forward=1"])

        iptc.Table(iptc.Table.NAT).flush()
        nat_rule = iptc.Rule()
        nat_rule.src = self.lan_config.network
        nat_rule.out_interface = self.lan_config.out_iface
        nat_rule.target = nat_rule.create_target("MASQUERADE")
        iptc.Chain(iptc.Table(iptc.Table.NAT), "POSTROUTING").append_rule(nat_rule)

        return self.is_running()
