import sys
from pathlib import Path
from subprocess import Popen

from jinja2 import Template


class DhcpConfig:
    def __init__(self, start_addr="192.168.0.50", end_addr="192.168.0.150", lease_time="12h"):
        self.config = {
            "start_addr": start_addr,
            "end_addr": end_addr,
            "lease_time": lease_time
        }

    def __str__(self):
        return "Start addr: {}\n" \
               "End addr: {}\n" \
               "Lease time: {}".format(self.config["start_addr"], self.config["end_addr"],
                                       self.config["lease_time"])


class WifiConfig:
    def __init__(self, interface="wlan0", channel=1, encryption="WPA2",password="password12345", essid="PINECONEWIFI"):
        self.config = {
            "interface": interface,
            "channel": channel,
            "encryption": encryption,
            "password": password,
            "essid": essid
        }

    def __str__(self):
        return "Interface: {}\n" \
               "Channel: {}\n" \
               "Encryption: {}\n" \
               "Password: {}\n" \
               "ESSID: {}".format(self.config["interface"], self.config["channel"],
                                  self.config["encryption"], self.config["password"],
                                  self.config["essid"])


class HostapdHandler:
    hostapd_cmd = "hostapd"
    hostapd_conf_template_path = Path(Path(__file__).parent, "templates", "hostapd_template.conf").resolve()
    # TODO: having only one config file allows only one AP to be up at a time.
    hostapd_conf_path = Path(Path(sys.modules["__main__"].__file__).parent, "tmp", "hostapd.conf").resolve()
    hostapd_conf_path.parent.mkdir(exist_ok=True)

    def __init__(self, wifi_config):
        self.wifi_config = wifi_config
        self.hostapd_process = None

    def is_running(self):
        return self.hostapd_process is not None and self.hostapd_process.poll() is None

    def stop(self):
        if self.is_running():
            self.hostapd_process.terminate()

    def run(self):
        template = Template(HostapdHandler.hostapd_conf_template_path.read_text())
        hostapd_conf = template.render(self.wifi_config.config)
        HostapdHandler.hostapd_conf_path.write_text(hostapd_conf)

        self.hostapd_process = Popen([HostapdHandler.hostapd_cmd, str(HostapdHandler.hostapd_conf_path)],
                                     stdout=sys.stdout, stderr=sys.stderr)


class DnsmasqHandler:
    dnsmasq_cmd = "dnsmasq"
    dnsmasq_conf_template_path = Path(Path(__file__).parent, "templates", "dnsmasq_template.conf").resolve()
    dnsmasq_conf_path = Path(Path(sys.modules["__main__"].__file__).parent, "tmp", "dnsmasq.conf").resolve()
    dnsmasq_conf_path.parent.mkdir(exist_ok=True)

    def __init__(self, dhcp_config):
        # TODO: IP config.
        self.dhcp_config = dhcp_config

    def is_running(self):
        # TODO
        pass

    def stop(self):
        # TODO
        pass

    def run(self):
        template = Template(DnsmasqHandler.dnsmasq_conf_template_path.read_text())
        dnsmasq_conf = template.render(self.dhcp_config.config)
        DnsmasqHandler.dnsmasq_conf_path.write_text(dnsmasq_conf)

        Popen([DnsmasqHandler.dnsmasq_cmd, "-C", str(DnsmasqHandler.dnsmasq_conf_path)])


class AP:
    def __init__(self, wifi_config, dhcp_config):
        self.wifi_config = wifi_config
        self.dhcp_config = dhcp_config

        self.hostapd_handler = HostapdHandler(self.wifi_config)
        self.dnsmasq_handler = DnsmasqHandler(self.dhcp_config)

    def __str__(self):
        return "Wifi config:\n" \
               "{}\n\n" \
               "DHCP config:\n" \
               "{}".format(self.wifi_config, self.dhcp_config)

    def is_running(self):
        # TODO
        return self.hostapd_handler.is_running()

    def stop(self):
        self.hostapd_handler.stop()
        self.dnsmasq_handler.stop()

    def start(self):
        self.hostapd_handler.run()
        self.dnsmasq_handler.run()
