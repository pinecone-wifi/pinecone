import importlib.util
import re
import sys
import shlex
import textwrap
from typing import Optional, Iterable, Sequence
from pathlib import Path

from prompt_toolkit import PromptSession, print_formatted_text
from prompt_toolkit.formatted_text import HTML
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.completion import NestedCompleter
from prompt_toolkit.shortcuts import radiolist_dialog
from prompt_toolkit.history import FileHistory

from sortedcontainers import SortedDict

from pinecone.core.database import Client, db_session, BasicServiceSet, ExtendedServiceSet

TMP_FOLDER_PATH: Path = Path(sys.path[0], "tmp").resolve()


class Pinecone():
    DEFAULT_PROMPT = HTML("<underline>pinecone</underline> > ")
    PROMPT_FORMAT = "<underline>pcn</underline> {}(<b fg='ansibrightred'>{}</b>) > "
    modules = SortedDict()

    def __init__(self):
        self.prompt = self.DEFAULT_PROMPT
        self.current_module_name = None
        self.current_module = None
        self.commands = SortedDict({
            "use": self.do_use,
            "exit": self.do_exit
        })

        TMP_FOLDER_PATH.mkdir(parents=True, exist_ok=True)

    def process_cmd(self, text: str):
        if not text.strip():
            return

        split_text = shlex.split(text)
        command = split_text[0]

        if command in self.commands:
            self.commands[command](split_text[1:] if len(split_text) > 1 else [])

    def cmdloop(self):
        session = PromptSession(history=FileHistory(Path(TMP_FOLDER_PATH, "pinecone_history")))

        while True:
            try:
                commands_completer_dict = {cmd: None for cmd in self.commands}
                commands_completer_dict["use"] = {module: None for module in self.modules}

                if self.current_module:
                    options_completer = {option.name: None for option in self.current_module.META["options"].values()}
                    commands_completer_dict["set"] = options_completer
                    commands_completer_dict["unset"] = options_completer

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

    def do_use(self, args: Sequence[str]) -> None:
        """Interact with the specified module."""

        if len(args) >= 1 and args[0] in self.modules:
            module = args[0]

            self.current_module = self.modules[module]
            self.current_module_name = module
            self.run_parser = self.current_module.META["options"]
            self.current_module.META["options"].prog = "run"
            self.commands["run"] = self.do_run
            self.commands["stop"] = self.do_stop
            self.commands["back"] = self.do_back
            self.commands["set"] = self.do_set
            self.commands["show"] = self.do_show
            self.commands["unset"] = self.do_unset

            if module.startswith("scripts/"):
                self.prompt = HTML(self.PROMPT_FORMAT.format("script", module.replace("scripts/", "")))
            else:
                self.prompt = HTML(self.PROMPT_FORMAT.format("module", module))

    run_parser = None

    def do_run(self, _) -> None:
        self.current_module.run(self.current_module.META["options"], self)

    def do_stop(self, _) -> None:
        self.current_module.stop(self)

    def do_back(self, _=None) -> None:
        if self.current_module:
            self.current_module = None
            self.current_module_name = None

            del self.commands["run"]
            del self.commands["stop"]
            del self.commands["back"]
            del self.commands["set"]
            del self.commands["show"]
            del self.commands["unset"]

            self.prompt = self.DEFAULT_PROMPT

    def do_exit(self, _):
        raise EOFError()

    def do_set(self, args: Sequence[str]):
        if len(args) >= 2 and args[0] in self.current_module.META["options"]:
            opt_name = args[0]
            opt_args = args[1:]

            try:
                self.current_module.META["options"][opt_name].parse(opt_args)
            except Exception as e:
                self.perror(f"The following option failed to validate: Value '{' '.join(opt_args)}' is not valid for "
                            f"option '{opt_name}'.")

            self.poutput(f"{opt_name} => {self.current_module.META['options'][opt_name].value_to_str()}")

    def do_unset(self, args: Sequence[str]):
        if len(args) >= 1 and args[0] in self.current_module.META["options"]:
            opt_name = args[0]
            self.current_module.META["options"][opt_name].value = None
            self.poutput(f"Unsetting {opt_name}...")

    def do_show(self, _):
        print(f"\nModule options ({self.current_module_name}):\n\n"
              f"{textwrap.indent(str(self.current_module.META['options']), ' '*3)}\n")

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
        print_formatted_text(HTML(f"<b fg='ansired'>[-]</b> "), end="")
        print(msg)

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
