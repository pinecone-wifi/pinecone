from jinja2 import Template
from pathlib import Path
from subprocess import Popen
import sys

class AP:
    hostapdPath = r"hostapd"
    hostapdConfTemplatePath = r"pinecone/core/hostapdTemplate.conf"
    hostapdConfPath = r"hostapd.conf"

    def __init__(self, interface, channel, encryption, passphrase, essid):
        self.interface = interface
        self.channel = channel
        self.encryption = encryption
        self.passphrase = passphrase
        self.essid = essid

        self.hostapdProcess = None

    def __str__(self):
        return "Interface: {}\n" \
               "SSID: {}\n" \
               "Channel: {}\n" \
               "Encryption: {}\n" \
               "Passphrase: {}".format(self.interface, self.essid, self.channel, self.encryption, self.passphrase)

    def isRunning(self):
        return self.hostapdProcess is not None and self.hostapdProcess.poll() is None

    def stop(self):
        if self.isRunning():
            self.hostapdProcess.terminate()

    def start(self):
        template = Template(Path(AP.hostapdConfTemplatePath).read_text())
        hostapdConf = template.render(interface=self.interface, channel=self.channel,
                                      encryption=self.encryption, passphrase=self.passphrase, ssid=self.essid)
        Path(AP.hostapdConfPath).write_text(hostapdConf)

        self.hostapdProcess = Popen(["hostapd", AP.hostapdConfPath], stdout=sys.stdout, stderr=sys.stderr)