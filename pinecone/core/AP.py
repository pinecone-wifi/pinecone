from jinja2 import Template
from pathlib import Path
import subprocess
import sys

class AP:
    HOSTAPD_TEMPLATE_PATH = r"pinecone/core/hostapdTemplate.conf"
    HOSTAPD_CONF_PATH = r"pinecone/core/hostapd.conf"

    def __init__(self, interface, channel, encryption, passphrase, essid):
        self.interface = interface
        self.channel = channel
        self.encryption = encryption
        self.passphrase = passphrase
        self.essid = essid

    def start(self):
        template = Template(Path(AP.HOSTAPD_TEMPLATE_PATH).read_text())
        hostapdConf = template.render(interface=self.interface, channel=self.channel,
                                      encryption=self.encryption, passphrase=self.passphrase, ssid=self.essid)
        Path(AP.HOSTAPD_CONF_PATH).write_text(hostapdConf)

        subprocess.run(["hostapd", AP.HOSTAPD_CONF_PATH], stdout=sys.stdout)