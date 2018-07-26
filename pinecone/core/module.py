import argparse
import sys
from abc import ABC, abstractmethod
from typing import Generator

from jinja2 import Template
from pathlib2 import Path
from psutil import process_iter, Process

from pinecone.core.main import Pinecone


class BaseModule(ABC):
    META = {
        "id": None,
        "name": None,
        "author": None,
        "version": None,
        "description": None,
        "options": None
    }

    @abstractmethod
    def run(self, args: argparse.Namespace, cmd: Pinecone) -> None:
        pass

    @abstractmethod
    def stop(self, cmd: Pinecone) -> None:
        pass


class DaemonBaseModule(BaseModule):
    TMP_FOLDER_PATH = Path(sys.path[0], "tmp").resolve()

    PROCESS_NAME = None
    CONFIG_TEMPLATE_PATH = None
    CONFIG_FILENAME = None

    @abstractmethod
    def __init__(self):
        self.process = None
        self.config_path = Path(self.TMP_FOLDER_PATH, self.CONFIG_FILENAME)

    def is_running(self) -> bool:
        return self.process is not None and self.process.is_running()

    def stop(self, cmd: Pinecone) -> None:
        if self.is_running():
            self.process.terminate()
            self.process = None

    @abstractmethod
    def launch(self) -> int:
        pass

    def run(self, args: argparse.Namespace, cmd: Pinecone) -> None:
        self._term_same_procs()

        config_template = Template(self.CONFIG_TEMPLATE_PATH.read_text())
        self.TMP_FOLDER_PATH.mkdir(exist_ok=True)
        self.config_path.write_text(config_template.render(vars(args)))

        if self.launch() == 0:
            self.process = next(self._search_same_procs(), None)

    @staticmethod
    def search_procs(process_name) -> Generator[Process, None, None]:
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
