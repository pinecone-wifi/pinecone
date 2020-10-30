import argparse
import importlib.util
import re
import sys
import shlex
from typing import Optional

from prompt_toolkit import PromptSession, print_formatted_text
from prompt_toolkit.formatted_text import FormattedText
from pathlib2 import Path

from pinecone.core.database import Client, db_session, BasicServiceSet, ExtendedServiceSet

TMP_FOLDER_PATH: Path = Path(sys.path[0], "tmp").resolve()


class Pinecone():
    DEFAULT_PROMPT = "pinecone > "
    PROMPT_FORMAT = "pcn {}({}) > "

    modules = {}

    def __init__(self):
        self.prompt = self.DEFAULT_PROMPT
        self.current_module = None
        self.commands = {
            "use": self.do_use,
            "exit": self.do_exit
        }

        TMP_FOLDER_PATH.mkdir(parents=True, exist_ok=True)

    def cmdloop(self):
        session = PromptSession()
        text = None

        while True:
            try:
                text = session.prompt(self.prompt)

                split_text = shlex.split(text)
                command = split_text[0]

                if command in self.commands:
                    self.commands[command](split_text[1:] if len(split_text) > 1 else [])
            except KeyboardInterrupt:
                continue
            except EOFError:
                break

    @classmethod
    def load_modules(cls) -> None:
        cls.modules.clear()
        modules_it = Path(sys.path[0], "modules").rglob("*.py")

        for py_file_path in modules_it:
            if py_file_path.stem == py_file_path.parent.name:
                module_name = "pinecone.{}".format(
                    re.search("modules/.*{}".format(py_file_path.stem), py_file_path.as_posix()).group().replace(
                        "/", "."))
                module_spec = importlib.util.spec_from_file_location(module_name, str(py_file_path))
                module = importlib.util.module_from_spec(module_spec)
                module_spec.loader.exec_module(module)
                module_class = module.Module
                cls.modules[module_class.META["id"]] = module_class()

    use_parser = argparse.ArgumentParser()
    use_parser.add_argument("module", choices=modules, type=str, help="module ID")

    def do_use(self, args: str) -> None:
        """Interact with the specified module."""

        args = self.use_parser.parse_args(args)

        if args.module in self.modules:
            self.current_module = self.modules[args.module]
            self.run_parser = self.current_module.META["options"]
            self.current_module.META["options"].prog = "run"
            self.commands["run"] = self.do_run

            if args.module.startswith("scripts/"):
                self.prompt = self.PROMPT_FORMAT.format("script", args.module.replace("scripts/", ""))
            else:
                self.prompt = self.PROMPT_FORMAT.format("module", args.module)

    run_parser = None

    def do_run(self, args: str) -> None:
        self.current_module.run(self.run_parser.parse_args(args), self)

    def do_stop(self, _: argparse.Namespace = None) -> None:
        self.current_module.stop(self)

    def do_back(self, _: argparse.Namespace = None) -> None:
        type(self).do_run = type(self).do_run
        self.prompt = self.DEFAULT_PROMPT

    def do_exit(self, _):
        raise EOFError()

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

    def poutput(self, msg: str):
        print(msg)

    def pfeedback(self, msg: str):
        print(msg)

    def perror(self, msg: str):
        print_formatted_text(FormattedText((("ansired", msg),)))