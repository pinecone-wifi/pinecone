import signal
import typing
from abc import ABC, abstractmethod
from copy import copy
from ipaddress import ip_network
from subprocess import run
from sys import modules

import iptc
from jinja2 import Template
from pathlib2 import Path
from psutil import process_iter
from pyric import pyw


class LanConfig:
    def __init__(self, router_ip="192.168.0.1", netmask="255.255.255.0", out_iface="eth0",
                 dhcp_start_addr="192.168.0.50", dhcp_end_addr="192.168.0.150", dhcp_lease_time="12h"):
        self.router_ip = router_ip
        self.netmask = netmask
        self.network = str(ip_network("{}/{}".format(self.router_ip, self.netmask), strict=False))
        self.out_iface = out_iface
        self.dhcp_start_addr = dhcp_start_addr
        self.dhcp_end_addr = dhcp_end_addr
        self.dhcp_lease_time = dhcp_lease_time

    def __str__(self):
        return "Router IP: {}\n" \
               "Netmask: {}\n" \
               "Network: {}\n" \
               "Out interface: {}\n" \
               "DHCP start addr: {}\n" \
               "DHCP end addr: {}\n" \
               "DHCP lease time: {}".format(self.router_ip, self.netmask, self.network, self.out_iface,
                                            self.dhcp_start_addr, self.dhcp_end_addr, self.dhcp_lease_time)


class WifiConfig:
    def __init__(self, interface="wlan0", channel=1, encryption="WPA2", password="password12345", essid="PINECONEWIFI"):
        self.interface = interface
        self.channel = channel
        self.encryption = encryption
        self.password = password
        self.essid = essid

    def __str__(self):
        return "Interface: {}\n" \
               "Channel: {}\n" \
               "Encryption: {}\n" \
               "Password: {}\n" \
               "ESSID: {}".format(self.interface, self.channel, self.encryption, self.password, self.essid)


class DaemonHandler(ABC):
    templates_folder_path = Path(Path(__file__).parent, "templates").resolve()
    tmp_folder_path = Path(Path(modules["__main__"].__file__).parent, "tmp").resolve()

    @abstractmethod
    def __init__(self, process_name: str, config_template_path: Path, config_path: Path, config):
        self.process = None
        self.process_name = process_name
        self.config_template_path = config_template_path
        self.config_path = config_path
        self.config = config

    def is_running(self):
        return self.process is not None and self.process.is_running()

    def stop(self):
        if self.is_running():
            self.process.terminate()

    @abstractmethod
    def launch(self):
        pass

    def run(self):
        self.term_same_procs()

        config_template = Template(self.config_template_path.read_text())
        DaemonHandler.tmp_folder_path.mkdir(exist_ok=True)
        self.config_path.write_text(config_template.render(vars(self.config)))

        if self.launch() == 0:
            self.process = next(self.search_same_procs(), None)

        return self.is_running()

    @staticmethod
    def search_procs(process_name):
        for p in process_iter(attrs=["name"]):
            if p.info["name"] == process_name:
                yield p

    def search_same_procs(self):
        return DaemonHandler.search_procs(self.process_name)

    def term_same_procs(self):
        for p in self.search_same_procs():
            p.terminate()


class HostapdHandler(DaemonHandler):
    def __init__(self, wifi_config: WifiConfig = None):
        if wifi_config is None:
            wifi_config = WifiConfig()

        super().__init__("hostapd", Path(DaemonHandler.templates_folder_path, "hostapd_template.conf").resolve(),
                         Path(DaemonHandler.tmp_folder_path, "hostapd.conf").resolve(), wifi_config)

    def launch(self):
        return run([self.process_name, "-B", str(self.config_path)]).returncode

    def run(self):
        for wpaSupplicantProc in DaemonHandler.search_procs("wpa_supplicant"):
            if any(self.config.interface in cmdLine for cmdLine in wpaSupplicantProc.cmdline()):
                wpaSupplicantProc.terminate()

        return super().run()


class DnsmasqHandler(DaemonHandler):
    custom_hosts_template_path = Path(DaemonHandler.templates_folder_path, "dnsmasq_custom_hosts_template").resolve()
    custom_hosts_path = Path(DaemonHandler.tmp_folder_path, "dnsmasq_custom_hosts").resolve()

    def __init__(self, lan_config: LanConfig = None, custom_hosts: typing.Dict[str, str] = None):
        if lan_config is None:
            lan_config = LanConfig()

        if custom_hosts is None:
            custom_hosts = dict()

        self.custom_hosts = custom_hosts

        config = copy(lan_config)
        config.custom_hosts_path = DnsmasqHandler.custom_hosts_path

        super().__init__("dnsmasq", Path(DaemonHandler.templates_folder_path, "dnsmasq_template.conf").resolve(),
                         Path(DaemonHandler.tmp_folder_path, "dnsmasq.conf").resolve(), config)

    def launch(self):
        return run([self.process_name, "-C", str(self.config_path)]).returncode

    def reload_custom_hosts(self):
        if self.is_running():
            self.render_custom_hosts_file()
            self.process.send_signal(signal.SIGHUP)

    def render_custom_hosts_file(self):
        custom_hosts_template = Template(DnsmasqHandler.custom_hosts_template_path.read_text())
        DaemonHandler.tmp_folder_path.mkdir(exist_ok=True)
        DnsmasqHandler.custom_hosts_path.write_text(custom_hosts_template.render(custom_hosts=self.custom_hosts))

    def run(self):
        self.render_custom_hosts_file()

        return super().run()


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

        self.hostapd_handler = HostapdHandler(self.wifi_config)
        self.dnsmasq_handler = DnsmasqHandler(self.lan_config, self.dns_custom_hosts)

    def __str__(self):
        return "Wifi config:\n" \
               "{}\n\n" \
               "LAN config:\n" \
               "{}".format(self.wifi_config, self.lan_config)

    def is_running(self):
        return self.hostapd_handler.is_running() and self.dnsmasq_handler.is_running()

    def reload_custom_hosts(self):
        self.dnsmasq_handler.reload_custom_hosts()

    def stop(self):
        self.hostapd_handler.stop()
        self.dnsmasq_handler.stop()

        run(["sysctl", "-w", "net.ipv4.ip_forward=0"])

        iptc.Table(iptc.Table.NAT).flush()

    def start(self):
        self.hostapd_handler.run()
        self.dnsmasq_handler.run()

        pyw.ifaddrset(pyw.getcard(self.wifi_config.interface), self.lan_config.router_ip, self.lan_config.netmask)

        run(["sysctl", "-w", "net.ipv4.ip_forward=1"])

        iptc.Table(iptc.Table.NAT).flush()
        nat_rule = iptc.Rule()
        nat_rule.src = self.lan_config.network
        nat_rule.out_interface = self.lan_config.out_iface
        nat_rule.target = nat_rule.create_target("MASQUERADE")
        iptc.Chain(iptc.Table(iptc.Table.NAT), "POSTROUTING").append_rule(nat_rule)

        return self.is_running()
