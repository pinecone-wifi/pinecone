import argparse
import signal
from subprocess import run

from jinja2 import Template
from pathlib2 import Path

from pinecone.core.main import Pinecone
from pinecone.core.module import DaemonBaseModule


class Module(DaemonBaseModule):
    META = {
        "id": "modules/server/dnsmasq",
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
    CONFIG_TEMPLATE_PATH = Path(Path(__file__).parent, "dnsmasq_template.conf").resolve()
    CONFIG_FILENAME = "dnsmasq.conf"

    CUSTOM_HOSTS_TEMPLATE_PATH = Path(Path(__file__).parent, "dnsmasq_custom_hosts_template").resolve()

    def __init__(self):
        self.custom_hosts_path = Path(self.TMP_FOLDER_PATH, "dnsmasq_custom_hosts").resolve()
        self.custom_hosts = {}

        super().__init__()

    def launch(self) -> int:
        return run([self.PROCESS_NAME, "-C", str(self.config_path)]).returncode

    def reload_custom_hosts(self):
        if self.is_running():
            self._render_custom_hosts_file()
            self.process.send_signal(signal.SIGHUP)

    def _render_custom_hosts_file(self):
        custom_hosts_template = Template(self.CUSTOM_HOSTS_TEMPLATE_PATH.read_text())
        self.TMP_FOLDER_PATH.mkdir(exist_ok=True)
        self.custom_hosts_path.write_text(custom_hosts_template.render(custom_hosts=self.custom_hosts))

    def run(self, args: argparse.Namespace, cmd: Pinecone) -> None:
        self._render_custom_hosts_file()
        args.custom_hosts_path = self.custom_hosts_path

        super().run(args, cmd)
