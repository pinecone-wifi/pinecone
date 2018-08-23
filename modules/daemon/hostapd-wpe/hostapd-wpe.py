import argparse
from subprocess import run

from pathlib2 import Path

from pinecone.core.module import DaemonBaseModule


class Module(DaemonBaseModule):
    META = {
        "id": "daemon/hostapd-wpe",
        "name": "hostapd-wpe daemon handler module",
        "author": "Valentín Blanco (https://github.com/valenbg1/)",
        "version": "1.0.0",
        "description": "Manages a hostapd-wpe daemon, which provides access point and authentication servers "
                       "functionalities. Supports impersonation attacks against 802.1X networks and also KARMA-style "
                       "gratuitous probe responses.",
        "options": argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter),
        "depends": {}
    }
    META["options"].add_argument("-i", "--iface", help="AP mode capable WLAN interface", default="wlan0",
                                 metavar="INTERFACE")
    META["options"].add_argument("-c", "--channel", help="AP channel", default=1, type=int)
    META["options"].add_argument("-e", "--encryption", help="AP encryption", default="WPA2",
                                 choices=("OPN", "WEP", "WPA", "WPA/WPA2", "WPA2"))
    META["options"].add_argument("-m", "--mgt", help="use MGT (802.1X) authn mode instead of PSK (for WPA modes)",
                                 action="store_true")
    META["options"].add_argument("-p", "--password", help="AP password (only for WEP or any WPA mode with PSK authn)",
                                 default="password12345")
    META["options"].add_argument("-s", "--ssid", help="AP SSID", default="PINECONEWIFI")
    META["options"].add_argument("-k", "--karma",
                                 help="respond to all directed probe requests (KARMA-style gratuitous probe responses)",
                                 action="store_true")
    META["options"].add_argument("--mac-acl",
                                 help="path to a MAC addresses whitelist. If specified, all the clients whose MAC "
                                      "address is not in this list will be rejected.",
                                 metavar="MAC_ACL_PATH")

    PROCESS_NAME = "hostapd-wpe"
    CONFIG_TEMPLATE_PATH = Path(Path(__file__).parent, "hostapd-wpe_template.conf").resolve()
    CONFIG_FILENAME = "hostapd-wpe.conf"

    def __init__(self):
        self.args = None

        super().__init__()

    def launch(self):
        cmdline_lst = [self.PROCESS_NAME, "-B", "-s"]

        if self.args.karma:
            cmdline_lst.append("-k")

        cmdline_lst.append(str(self.config_path))

        return run(cmdline_lst).returncode

    def run(self, args, cmd):
        self.args = args

        for wpaSupplicantProc in self.search_procs("wpa_supplicant"):
            if any(args.iface in cmdLine for cmdLine in wpaSupplicantProc.cmdline()):
                wpaSupplicantProc.terminate()

        super().run(args, cmd)
