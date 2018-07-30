import argparse
import signal
from subprocess import run
from typing import Any

from pathlib2 import Path

from pinecone.core.main import Pinecone
from pinecone.core.module import DaemonBaseModule
from pinecone.utils.template import render_template


class Module(DaemonBaseModule):
    META = {
        "id": "modules/daemon/dnsmasq",
        "name": "",
        "author": "",
        "version": "",
        "description": "",
        "options": argparse.ArgumentParser()
    }
    META["options"].add_argument("-s", "--start-addr", help="DHCP start address.", default="192.168.0.50", type=str)
    META["options"].add_argument("-e", "--end-addr", help="DHCP end address.", default="192.168.0.150", type=str)
    META["options"].add_argument("-l", "--lease-time", help="DHCP lease time.", default="12h", type=str)

    PROCESS_NAME = "dnsmasq"
    CONFIG_TEMPLATE_PATH = Path(Path(__file__).parent, "dnsmasq_template.conf").resolve()  # type: Path
    CONFIG_FILENAME = "dnsmasq.conf"

    CUSTOM_HOSTS_TEMPLATE_PATH = Path(Path(__file__).parent, "dnsmasq_custom_hosts_template").resolve()  # type: Path

    def __init__(self):
        self.custom_hosts_path = Path(self.TMP_FOLDER_PATH, "dnsmasq_custom_hosts").resolve()
        self.custom_hosts = {}

        super().__init__()

    def launch(self) -> int:
        return run([self.PROCESS_NAME, "-C", str(self.config_path)]).returncode

    def reload_custom_hosts(self) -> None:
        if self.is_running():
            self._render_custom_hosts_file()
            self.process.send_signal(signal.SIGHUP)

    def _render_custom_hosts_file(self) -> None:
        render_template(self.CUSTOM_HOSTS_TEMPLATE_PATH, self.custom_hosts_path, {
            "custom_hosts": self.custom_hosts
        })

    def run(self, args: argparse.Namespace, cmd: Pinecone) -> Any:
        self._render_custom_hosts_file()
        args.custom_hosts_path = self.custom_hosts_path

        super().run(args, cmd)
