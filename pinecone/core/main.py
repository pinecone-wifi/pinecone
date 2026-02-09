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
        self.prompt = self.DEFAULT_PROMPT
        self.current_module = None

        TMP_FOLDER_PATH.mkdir(parents=True, exist_ok=True)

        super().__init__(persistent_history_file=str(Path(TMP_FOLDER_PATH, "pinecone_history")),
                         persistent_history_length=500)

    @classmethod
    def reload_modules(cls) -> None:
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

    use_parser = Cmd2ArgumentParser()
    use_module_action = use_parser.add_argument("module", choices=modules, type=str, help="module ID")

    def do_reload(self):
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

    """
    session_actions = {'checkout', 'delete', 'list', 'info'}
    session_parser = Cmd2ArgumentParser()
    session_module_action = session_parser.add_argument(
        "action",
        type=str,
        help="session action",
        choices=session_actions,
    )
    session_parser.add_argument(
        "session",
        type=str,
        nargs="?",
        help="Session name can only contain letters numbers and underscores (my_session_01)",
        default='default'
    )

    @cmd2.with_argparser(session_parser)
    @db_session
    def do_session(self, args: argparse.Namespace) -> None:
        '''Interact with sessions.'''

        target_session = args.session
        if not re.match(r"\w+[\w_]*", target_session):
            self.perror("Invalid session name")
            return

        if args.action == "checkout":
            self.session = target_session
        elif args.action == "delete":
            curr_session = self.session
            target_session = curr_session if target_session == 'default' else target_session

            deleted_session_name = target_session
            if deleted_session_name == curr_session:
                # Switch to default session prior to session delete
                deleted_session_name = curr_session
                self.session = "default"

            try:
                Session[deleted_session_name].delete()
            except Exception as e:
                self.perror("Error deleting session {}".format(deleted_session_name), e)

        elif args.action == "list":
            self.pfeedback("{:25}\t{}".format("Session Name", "Creation Date"))
            for session in Session.select():
                self.pfeedback(
                    "{:25}\t{}".format(
                        session.name,
                        session.creation_date
                    )
                )

        elif args.action == "info":
            curr_session = self.session
            target_session = curr_session if target_session == 'default' else target_session

            try:
                session = Session[target_session]
                self.pfeedback(
                    "Name: {}\nCreation Date: {}\n#Clients: {}\n#BSS: {}\n#ESS: {}".format(
                        session.name,
                        session.creation_date,
                        session.clients.count(),
                        session.bsss.count(),
                        session.esss.count()
                    )
                )
            except ObjectNotFound:
                self.pfeedback("ERROR: Session not found in database")
    """

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
