import sys
from abc import ABC, abstractmethod

import psutil
from jinja2 import Template
from pathlib2 import Path
from pyric import pyw


class LanConfig:
    def __init__(self, router_ip="192.168.0.1", netmask="255.255.255.0", dhcp_start_addr="192.168.0.50",
                 dhcp_end_addr="192.168.0.150", dhcp_lease_time="12h"):
        self.router_ip = router_ip
        self.netmask = netmask
        self.dhcp_start_addr = dhcp_start_addr
        self.dhcp_end_addr = dhcp_end_addr
        self.dhcp_lease_time = dhcp_lease_time

    def __str__(self):
        return "Router IP: {}\n" \
               "Netmask: {}\n" \
               "DHCP start addr: {}\n" \
               "DHCP end addr: {}\n" \
               "DHCP lease time: {}".format(self.router_ip, self.netmask, self.dhcp_start_addr, self.dhcp_end_addr,
                                            self.dhcp_lease_time)


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
    config_templates_folder_path = Path(Path(__file__).parent, "templates").resolve()
    configs_folder_path = Path(Path(sys.modules["__main__"].__file__).parent, "tmp").resolve()

    @abstractmethod
    def __init__(self, process_name, config_template_path, config_path, config):
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

        template = Template(self.config_template_path.read_text())
        self.config_path.parent.mkdir(exist_ok=True)
        self.config_path.write_text(template.render(vars(self.config)))

        if self.launch() == 0:
            self.process = next(self.search_same_procs(), None)

        return self.is_running()

    def search_same_procs(self):
        for p in psutil.process_iter(attrs=["name"]):
            if p.info["name"] == self.process_name:
                yield p

    def term_same_procs(self):
        for p in self.search_same_procs():
            p.terminate()


class HostapdHandler(DaemonHandler):
    def __init__(self, wifi_config=WifiConfig()):
        super().__init__("hostapd", Path(DaemonHandler.config_templates_folder_path, "hostapd_template.conf").resolve(),
                         Path(DaemonHandler.configs_folder_path, "hostapd.conf").resolve(),
                         wifi_config)

    def launch(self):
        return psutil.Popen([self.process_name, "-B", str(self.config_path)]).wait()


class DnsmasqHandler(DaemonHandler):
    def __init__(self, lan_config=LanConfig()):
        super().__init__("dnsmasq", Path(DaemonHandler.config_templates_folder_path, "dnsmasq_template.conf").resolve(),
                         Path(DaemonHandler.configs_folder_path, "dnsmasq.conf").resolve(),
                         lan_config)

    def launch(self):
        return psutil.Popen([self.process_name, "-C", str(self.config_path)]).wait()


class AP:
    def __init__(self, wifi_config=WifiConfig(), lan_config=LanConfig()):
        self.wifi_config = wifi_config
        self.lan_config = lan_config

        self.hostapd_handler = HostapdHandler(self.wifi_config)
        self.dnsmasq_handler = DnsmasqHandler(self.lan_config)

    def __str__(self):
        return "Wifi config:\n" \
               "{}\n\n" \
               "LAN config:\n" \
               "{}".format(self.wifi_config, self.lan_config)

    def is_running(self):
        return self.hostapd_handler.is_running() and self.dnsmasq_handler.is_running()

    def stop(self):
        self.hostapd_handler.stop()
        self.dnsmasq_handler.stop()

    def start(self):
        self.hostapd_handler.run()
        self.dnsmasq_handler.run()

        pyw.ifaddrset(pyw.getcard(self.wifi_config.interface), self.lan_config.router_ip, self.lan_config.netmask)
