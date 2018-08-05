import argparse
from subprocess import run

from pathlib2 import Path

from pinecone.core.module import DaemonBaseModule


class Module(DaemonBaseModule):
    META = {
        "id": "daemon/hostapd",
        "name": "hostapd daemon handler module",
        "author": "Valentín Blanco (https://github.com/valenbg1/)",
        "version": "1.0.0",
        "description": "Manages a hostapd daemon, which provides access point and authentication servers functionalities.",
        "options": argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter),
        "depends": {}
    }
    META["options"].add_argument("-i", "--iface", help="AP mode capable WLAN interface", default="wlan0")
    META["options"].add_argument("-c", "--channel", help="AP channel", default=1, type=int)
    META["options"].add_argument("-e", "--encryption", help="AP encryption", default="WPA2")
    META["options"].add_argument("-p", "--password", help="AP password", default="password12345")
    META["options"].add_argument("-s", "--ssid", help="AP SSID", default="PINECONEWIFI")

    PROCESS_NAME = "hostapd"
    CONFIG_TEMPLATE_PATH = Path(Path(__file__).parent, "hostapd_template.conf").resolve()  # type: Path
    CONFIG_FILENAME = "hostapd.conf"

    def __init__(self):
        super().__init__()

    def launch(self):
        return run([self.PROCESS_NAME, "-B", str(self.config_path)]).returncode

    def run(self, args, cmd):
        for wpaSupplicantProc in self.search_procs("wpa_supplicant"):
            if any(args.iface in cmdLine for cmdLine in wpaSupplicantProc.cmdline()):
                wpaSupplicantProc.terminate()

        super().run(args, cmd)
