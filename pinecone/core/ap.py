import sys
from pathlib import Path
from subprocess import Popen

from jinja2 import Template


class AP:
    hostapdCmd = "hostapd"
    hostapdConfTemplatePath = Path(Path(__file__).parent, "hostapd_template.conf").resolve()
    hostapdConfPath = Path(Path(sys.modules["__main__"].__file__).parent, "tmp", "hostapd.conf").resolve()
    hostapdConfPath.parent.mkdir(exist_ok=True)


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
        template = Template(AP.hostapdConfTemplatePath.read_text())
        hostapdConf = template.render(interface=self.interface, channel=self.channel,
                                      encryption=self.encryption, passphrase=self.passphrase, ssid=self.essid)
        AP.hostapdConfPath.write_text(hostapdConf)

        self.hostapdProcess = Popen([AP.hostapdCmd, str(AP.hostapdConfPath)], stdout=sys.stdout, stderr=sys.stderr)
