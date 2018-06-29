import subprocess
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


class Handler(ABC):
    @abstractmethod
    def __init__(self):
        self.process = None
        self.process_name = None
        self.config_template_path = None
        self.config_path = None
        self.config = None

    @abstractmethod
    def is_running(self):
        return self.process is not None and self.process.is_running()

    @abstractmethod
    def stop(self):
        if self.is_running():
            self.process.terminate()

    @abstractmethod
    def run(self):
        self.term_same_procs()

        template = Template(self.config_template_path.read_text())
        self.config_path.parent.mkdir(exist_ok=True)
        self.config_path.write_text(template.render(vars(self.config)))

    def term_same_procs(self):
        for p in psutil.process_iter(attrs=["name"]):
            if p.info["name"] == self.process_name:
                p.terminate()


class HostapdHandler:
    hostapd_cmd = "hostapd"
    hostapd_conf_template_path = Path(Path(__file__).parent, "templates", "hostapd_template.conf").resolve()
    # TODO: having only one config file allows only one AP to be up at a time.
    hostapd_conf_path = Path(Path(sys.modules["__main__"].__file__).parent, "tmp", "hostapd.conf").resolve()

    def __init__(self, wifi_config=WifiConfig()):
        self.wifi_config = wifi_config
        self.hostapd_process = None

    def is_running(self):
        return self.hostapd_process is not None and self.hostapd_process.poll() is None

    def stop(self):
        if self.is_running():
            self.hostapd_process.terminate()

    def run(self):
        template = Template(HostapdHandler.hostapd_conf_template_path.read_text())
        hostapd_conf = template.render(vars(self.wifi_config))
        HostapdHandler.hostapd_conf_path.parent.mkdir(exist_ok=True)
        HostapdHandler.hostapd_conf_path.write_text(hostapd_conf)

        self.hostapd_process = subprocess.Popen([HostapdHandler.hostapd_cmd, str(HostapdHandler.hostapd_conf_path)],
                                                stdout=sys.stdout, stderr=sys.stderr)


class DnsmasqHandler:
    dnsmasq_cmd = "dnsmasq"
    dnsmasq_conf_template_path = Path(Path(__file__).parent, "templates", "dnsmasq_template.conf").resolve()
    dnsmasq_conf_path = Path(Path(sys.modules["__main__"].__file__).parent, "tmp", "dnsmasq.conf").resolve()

    def __init__(self, lan_config=LanConfig()):
        self.lan_config = lan_config

    def is_running(self):
        # TODO
        pass

    def stop(self):
        # TODO
        pass

    def run(self):
        template = Template(DnsmasqHandler.dnsmasq_conf_template_path.read_text())
        dnsmasq_conf = template.render(vars(self.lan_config))
        DnsmasqHandler.dnsmasq_conf_path.parent.mkdir(exist_ok=True)
        DnsmasqHandler.dnsmasq_conf_path.write_text(dnsmasq_conf)

        subprocess.run([DnsmasqHandler.dnsmasq_cmd, "-C", str(DnsmasqHandler.dnsmasq_conf_path)])


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
        # TODO
        return self.hostapd_handler.is_running()

    def stop(self):
        self.hostapd_handler.stop()
        self.dnsmasq_handler.stop()

    def start(self):
        self.hostapd_handler.run()
        self.dnsmasq_handler.run()

        pyw.ifaddrset(pyw.getcard(self.wifi_config.interface), self.lan_config.router_ip, self.lan_config.netmask)
