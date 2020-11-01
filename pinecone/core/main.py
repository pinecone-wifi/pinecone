import argparse
import importlib.util
import re
import sys
import shlex
from typing import Optional, Iterable, List

from prompt_toolkit import PromptSession, print_formatted_text
from prompt_toolkit.formatted_text import FormattedText
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.completion import NestedCompleter
from prompt_toolkit.shortcuts import radiolist_dialog
from pathlib2 import Path

from pinecone.core.database import Client, db_session, BasicServiceSet, ExtendedServiceSet

TMP_FOLDER_PATH: Path = Path(sys.path[0], "tmp").resolve()


class Pinecone():
    DEFAULT_PROMPT = FormattedText((("underline", "pinecone"),
                                   ("", " > ")))
    PROMPT_FORMAT = FormattedText((("underline", "pcn"),
                                   ("", " {}("),
                                   ("bold ansibrightred", "{}"),
                                   ("", ") > ")))
    modules = {}

    def __init__(self):
        self.prompt = self.DEFAULT_PROMPT
        self.current_module = None
        self.commands = {
            "use": self.do_use,
            "exit": self.do_exit
        }

        TMP_FOLDER_PATH.mkdir(parents=True, exist_ok=True)

    def process_cmd(self, text: str):
        if not text.strip():
            return

        split_text = shlex.split(text)
        command = split_text[0]

        if command in self.commands:
            self.commands[command](split_text[1:] if len(split_text) > 1 else [])

    def cmdloop(self):
        session = PromptSession()

        while True:
            try:
                commands_completer_dict = {cmd: None for cmd in self.commands}
                commands_completer_dict["use"] = {module: None for module in self.modules}
                commands_completer = NestedCompleter.from_nested_dict(commands_completer_dict)
                self.process_cmd(session.prompt(self.prompt, auto_suggest=AutoSuggestFromHistory(),
                                                completer=commands_completer))
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

    def do_use(self, args: List[str]) -> None:
        """Interact with the specified module."""

        try:
            args = self.use_parser.parse_args(args)
        except SystemExit:
            return

        if args.module in self.modules:
            self.current_module = self.modules[args.module]
            self.run_parser = self.current_module.META["options"]
            self.current_module.META["options"].prog = "run"
            self.commands["run"] = self.do_run
            self.commands["stop"] = self.do_stop
            self.commands["back"] = self.do_back

            if args.module.startswith("scripts/"):
                self.prompt = FormattedText(self.PROMPT_FORMAT)
                self.prompt[1] = (self.prompt[1][0], self.prompt[1][1].format("script"))
                self.prompt[2] = (self.prompt[2][0], args.module.replace("scripts/", ""))
            else:
                self.prompt = FormattedText(self.PROMPT_FORMAT)
                self.prompt[1] = (self.prompt[1][0], self.prompt[1][1].format("module"))
                self.prompt[2] = (self.prompt[2][0], args.module)

    run_parser = None

    def do_run(self, args: List[str]) -> None:
        try:
            args = self.run_parser.parse_args(args)
        except SystemExit:
            return

        self.current_module.run(args, self)

    def do_stop(self, _: argparse.Namespace = None) -> None:
        self.current_module.stop(self)

    def do_back(self, _: argparse.Namespace = None) -> None:
        if "back" in self.commands:
            del self.commands["run"]
            del self.commands["stop"]
            del self.commands["back"]

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

    @classmethod
    def poutput(cls, msg: str):
        print(msg)

    @classmethod
    def pfeedback(cls, msg: str):
        print(msg)

    @classmethod
    def perror(cls, msg: str):
        print_formatted_text(FormattedText((("ansired", msg),)))

    @classmethod
    def select(cls, choices_lst: Iterable, msg: str):
        return radiolist_dialog(
            title="Selection dialog",
            text=msg,
            values=[(choice, choice) for choice in choices_lst]
        ).run()

    def do_run_script(self, script_path: Path):
        with open(script_path, "r") as script:
            for line in script:
                self.process_cmd(line)
