import argparse
import importlib.util
import re
import sys
from typing import Optional

import cmd2
from cmd2 import Cmd2ArgumentParser
from pathlib2 import Path

from pinecone.core.database import Client, db_session, BasicServiceSet, ExtendedServiceSet

TMP_FOLDER_PATH: Path = Path(sys.path[0], "tmp").resolve()


class Pinecone(cmd2.Cmd):
    DEFAULT_PROMPT = "pinecone > "
    PROMPT_FORMAT = "pcn {}({}) > "

    modules = {}

    def __init__(self):
        self.current_module = None

        TMP_FOLDER_PATH.mkdir(parents=True, exist_ok=True)

        super().__init__(persistent_history_file=str(Path(TMP_FOLDER_PATH, "pinecone_history")),
                         persistent_history_length=500)
        
        self.prompt = self.DEFAULT_PROMPT

    @classmethod
    def reload_modules(cls) -> None:
        cls.modules.clear()
        modules_it = Path(sys.path[0], "modules").rglob("*.py")

        for py_file_path in modules_it:
            if py_file_path.stem == py_file_path.parent.name:
                try:
                    module_name = "pinecone.{}".format(
                        re.search("modules/.*{}".format(py_file_path.stem), py_file_path.as_posix()).group().replace(
                            "/", "."))
                    module_spec = importlib.util.spec_from_file_location(module_name, str(py_file_path))
                    module = importlib.util.module_from_spec(module_spec)
                    module_spec.loader.exec_module(module)
                    module_class = module.Module
                    cls.modules[module_class.META["id"]] = module_class()
                except Exception as ex:
                    pass
        
        # Update parser choices with loaded modules
        cls.use_module_action.choices = list(cls.modules.keys())

    use_parser = Cmd2ArgumentParser()
    use_module_action = use_parser.add_argument("module", choices=list(modules.keys()), type=str, help="module ID")

    def do_reload(self, _):
        self.pfeedback("Reloading modules.")
        self.reload_modules()

    @cmd2.with_argparser(use_parser)
    def do_use(self, args: argparse.Namespace) -> None:
        """Interact with the specified module."""

        if args.module in self.modules:
            self.current_module = self.modules[args.module]
            type(self).do_run = cmd2.with_argparser(self.current_module.META["options"])(type(self)._do_run)
            self.current_module.META["options"].prog = "run"

            if args.module.startswith("scripts/"):
                self.prompt = self.PROMPT_FORMAT.format("script", args.module.replace("scripts/", ""))
            else:
                self.prompt = self.PROMPT_FORMAT.format("module", args.module)

    def _do_run(self, args: argparse.Namespace) -> None:
        self.current_module.run(args, self)

    do_run = _do_run

    def do_stop(self, _: argparse.Namespace = None) -> None:
        self.current_module.stop(self)

    def do_back(self, _: argparse.Namespace = None) -> None:
        type(self).do_run = type(self)._do_run
        self.prompt = self.DEFAULT_PROMPT

    def do_exit(self, _):
        return self.do_quit(_)

    @db_session
    def select_bss(self, ssid: Optional[str] = None, bssid: Optional[str] = None,
                   client_mac: Optional[str] = None) -> Optional[Client]:
        if bssid:
            return BasicServiceSet.get(bssid=bssid)

        ess = ExtendedServiceSet.get(ssid=ssid) if ssid else None
        client = Client.get(mac=client_mac) if client_mac else None

        if ess and not ess.bssets.is_empty():
            if ess.bssets.count() == 1:
                bssid = ess.bssets.select().first().bssid
            else:
                self.pfeedback('SSID "{}" is associated with multiple BSSIDs, select the appropiate:'.format(ssid))
                bssid = self.select(sorted(bss.bssid for bss in ess.bssets), "Option: ")

        if not bssid and client and not client.connections.is_empty():
            if client.connections.count() == 1:
                bssid = client.connections.select().first().bss.bssid
            else:
                self.pfeedback(
                    "Client {} is associated with multiple BSSIDs, select the appropiate:".format(client_mac)
                )
                bssid = self.select(sorted(conn.bss.bssid for conn in client.connections), "Option: ")

        if bssid:
            return BasicServiceSet.get(bssid=bssid)
