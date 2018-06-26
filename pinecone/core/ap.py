import sys
from pathlib import Path
from subprocess import Popen

from jinja2 import Template


class AP:
    hostapd_cmd = "hostapd"
    hostapd_conf_template_path = Path(Path(__file__).parent, "hostapd_template.conf").resolve()
    # TODO: Muliple APs configuration files.
    hostapd_conf_path = Path(Path(sys.modules["__main__"].__file__).parent, "tmp", "hostapd.conf").resolve()
    hostapd_conf_path.parent.mkdir(exist_ok=True)

    dnsmasq_cmd = "dnsmasq"
    dnsmasq_conf_template_path = Path(Path(__file__).parent, "dnsmasq_template.conf").resolve()
    dnsmasq_conf_path = Path(Path(sys.modules["__main__"].__file__).parent, "tmp", "dnsmasq.conf").resolve()
    dnsmasq_conf_path.parent.mkdir(exist_ok=True)

    def __init__(self, interface, channel, encryption, passphrase, essid):
        self.interface = interface
        self.channel = channel
        self.encryption = encryption
        self.passphrase = passphrase
        self.essid = essid
        self.hostapd_process = None

    def __str__(self):
        return "Interface: {}\n" \
               "SSID: {}\n" \
               "Channel: {}\n" \
               "Encryption: {}\n" \
               "Passphrase: {}".format(self.interface, self.essid, self.channel, self.encryption, self.passphrase)

    def is_running(self):
        return self.hostapd_process is not None and self.hostapd_process.poll() is None

    def stop(self):
        if self.is_running():
            self.hostapd_process.terminate()

    def start(self):
        template = Template(AP.hostapd_conf_template_path.read_text())
        hostapd_conf = template.render(interface=self.interface, channel=self.channel,
                                       encryption=self.encryption, passphrase=self.passphrase, ssid=self.essid)
        AP.hostapd_conf_path.write_text(hostapd_conf)
        self.hostapd_process = Popen([AP.hostapd_cmd, str(AP.hostapd_conf_path)], stdout=sys.stdout, stderr=sys.stderr)

        AP.dnsmasq_conf_path.write_text(AP.dnsmasq_conf_template_path.read_text())
        Popen([AP.dnsmasq_cmd, "-C", str(AP.dnsmasq_conf_path)])
