import argparse
from subprocess import run

from pathlib2 import Path

from pinecone.core.module import DaemonBaseModule
from pinecone.core.options import OptionDict, Option


class Module(DaemonBaseModule):
    META = {
        "id": "daemon/hostapd-wpe",
        "name": "hostapd-wpe daemon handler module",
        "author": "Valentín Blanco (https://github.com/valenbg1)",
        "version": "1.0.0",
        "description": "Manages a hostapd-wpe daemon, which provides access point and authentication servers "
                       "functionalities. Supports impersonation attacks against 802.1X networks and also KARMA-style "
                       "gratuitous probe responses.",
        "options": OptionDict(),
        "depends": {}
    }
    META["options"].add(Option("INTERFACE", "wlan0", True, "AP mode capable WLAN interface"))
    META["options"].add(Option("CHANNEL", 1, True, "AP channel", int))
    META["options"].add(Option("ENCRYPTION", "WPA2", True, "AP encryption",
                               choices=("OPN", "WEP", "WPA", "WPA/WPA2", "WPA2")))
    META["options"].add(Option("MGT", False, True, "use MGT (802.1X) authn mode instead of PSK (for WPA modes)", bool))
    META["options"].add(Option("PASSWORD", "password12345", False, "AP password (only for WEP or any WPA mode with PSK "
                                                                   "authn)"))
    META["options"].add(Option("SSID", "PINECONEWIFI", True, "AP SSID"))
    META["options"].add(Option("KARMA", False, True, "respond to all directed probe requests (KARMA-style gratuitous "
                                                     "probe responses)", bool))
    META["options"].add(Option("MAC_ACL", description="path to a MAC addresses whitelist. If specified, all the "
                                                      "clients whose MAC address is not in this list will be "
                                                      "rejected."))

    PROCESS_NAME = "hostapd-wpe"
    CONFIG_TEMPLATE_PATH = Path(Path(__file__).parent, "hostapd-wpe_template.conf").resolve()
    CONFIG_FILENAME = "hostapd-wpe.conf"

    def __init__(self):
        self.opts = None

        super().__init__()

    def launch(self):
        cmdline_lst = [self.PROCESS_NAME, "-B", "-s"]

        if self.opts.karma:
            cmdline_lst.append("-k")

        cmdline_lst.append(str(self.config_path))

        return run(cmdline_lst).returncode

    def run(self, opts, cmd):
        opts = opts.get_opts_namespace()
        self.opts = opts

        for wpaSupplicantProc in self.search_procs("wpa_supplicant"):
            if any(opts.interface in cmdLine for cmdLine in wpaSupplicantProc.cmdline()):
                wpaSupplicantProc.terminate()

        super().run(opts, cmd)
