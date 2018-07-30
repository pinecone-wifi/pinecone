import argparse
from subprocess import run
from typing import Any

from pathlib2 import Path

from pinecone.core.main import Pinecone
from pinecone.core.module import DaemonBaseModule


class Module(DaemonBaseModule):
    META = {
        "id": "modules/daemon/hostapd",
        "name": "",
        "author": "",
        "version": "",
        "description": "",
        "options": argparse.ArgumentParser()
    }
    META["options"].add_argument("-i", "--iface", help="wlan interface", default="wlan0", type=str)
    META["options"].add_argument("-c", "--channel", default=1, type=int)
    META["options"].add_argument("-e", "--encryption", default="WPA2", type=str)
    META["options"].add_argument("-p", "--password", default="password12345", type=str)
    META["options"].add_argument("-s", "--ssid", default="PINECONEWIFI", type=str)

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
