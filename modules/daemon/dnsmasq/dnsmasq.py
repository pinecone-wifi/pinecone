import signal
from subprocess import run
from pathlib import Path

from pinecone.core.main import TMP_FOLDER_PATH
from pinecone.core.module import DaemonBaseModule
from pinecone.utils.template import render_template
from pinecone.core.options import OptionDict, Option


class Module(DaemonBaseModule):
    META = {
        "id": "daemon/dnsmasq",
        "name": "Dnsmasq daemon handler module",
        "author": "Valentín Blanco (https://github.com/valenbg1)",
        "version": "1.0.0",
        "description": "Manages a dnsmasq daemon server, which provides DNS and DHCP services.",
        "options": OptionDict(),
        "depends": {}
    }
    META["options"].add(Option("START_ADDR", "192.168.0.50", "DHCP start address"))
    META["options"].add(Option("END_ADDR", "192.168.0.150", "DHCP end address"))
    META["options"].add(Option("LEASE_TIME", "12h", "DHCP lease time"))

    PROCESS_NAME = "dnsmasq"
    CONFIG_TEMPLATE_PATH = Path(Path(__file__).parent, "dnsmasq_template.conf").resolve()  # type: Path
    CONFIG_FILENAME = "dnsmasq.conf"

    CUSTOM_HOSTS_TEMPLATE_PATH = Path(Path(__file__).parent, "dnsmasq_custom_hosts_template").resolve()  # type: Path

    def __init__(self):
        self.custom_hosts_path = Path(TMP_FOLDER_PATH, "dnsmasq_custom_hosts").resolve()
        self.custom_hosts = {}

        super().__init__()

    def launch(self):
        return run([self.PROCESS_NAME, "-C", str(self.config_path)]).returncode

    def reload_custom_hosts(self) -> None:
        if self.is_running():
            self._render_custom_hosts_file()
            self.process.send_signal(signal.SIGHUP)

    def _render_custom_hosts_file(self) -> None:
        render_template(self.CUSTOM_HOSTS_TEMPLATE_PATH, self.custom_hosts_path, {
            "custom_hosts": self.custom_hosts
        })

    def run(self, opts, cmd):
        opts = opts.get_opts_namespace()

        self._render_custom_hosts_file()
        opts.custom_hosts_path = self.custom_hosts_path

        super().run(opts, cmd)
