import argparse
from abc import ABC, abstractmethod
from typing import Generator, Dict, Any

from pathlib2 import Path
from psutil import process_iter, Process

from pinecone.core.main import Pinecone, TMP_FOLDER_PATH
from pinecone.utils.template import render_template


class BaseModule(ABC):
    # Module's meta-information.
    META: Dict[str, Any] = {
        # ID of the module as it would appear in the directories tree.
        "id": None,
        # Module's short name.
        "name": None,
        # Module's author.
        "author": None,
        # Module's version.
        "version": None,
        # Module's long description.
        "description": None,
        # Module's options. It can be an argparse.ArgumentParser or a cmd2.argparse_completer.ACArgumentParser for
        # leveraging cmd2's auto-completion.
        "options": None,
        # Set of module's dependencies. They can be either Python packages and, in the case of developing a Pinecone
        # extension script, also other modules IDs.
        "depends": None
    }

    @abstractmethod
    def run(self, args: argparse.Namespace, cmd: Pinecone) -> Any:
        """
        Implements the module's main functionality.
        :param args: this method receives the options parsed in this parameter, as an argparse.Namespace instance.
        :param cmd: an instance of Pinecone's main cmd2 object, which can be primarily used for providing feedback to
                    the user.
        :return: this method can return anything.
        """

        pass

    @abstractmethod
    def stop(self, cmd: Pinecone) -> Any:
        """
        Implements the module's stop functionality (for example, in case the module stays running in the background).
        :param cmd: an instance of Pinecone's main cmd2 object, which can be primarily used for providing feedback to
                    the user.
        :return: this method can return anything.
        """

        pass


class DaemonBaseModule(BaseModule):
    PROCESS_NAME: str = None
    CONFIG_TEMPLATE_PATH: Path = None
    CONFIG_FILENAME: str = None

    @abstractmethod
    def __init__(self):
        self.process = None
        self.config_path = Path(TMP_FOLDER_PATH, self.CONFIG_FILENAME)

    def is_running(self) -> bool:
        return self.process is not None and self.process.is_running()

    def stop(self, cmd: Pinecone) -> Any:
        if self.is_running():
            self.process.terminate()
            self.process = None

    @abstractmethod
    def launch(self) -> int:
        pass

    def run(self, opts, cmd: Pinecone) -> Any:
        self._term_same_procs()

        render_template(self.CONFIG_TEMPLATE_PATH, self.config_path, opts)

        if self.launch() == 0:
            self.process = next(self._search_same_procs(), None)

    @staticmethod
    def search_procs(process_name: str) -> Generator[Process, None, None]:
        for p in process_iter(attrs=["name"]):
            if p.info["name"] == process_name:
                yield p

    @classmethod
    def _search_same_procs(cls) -> Generator[Process, None, None]:
        return cls.search_procs(cls.PROCESS_NAME)

    @classmethod
    def _term_same_procs(cls) -> None:
        for p in cls._search_same_procs():
            p.terminate()
