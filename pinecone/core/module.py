import argparse
import sys
from abc import ABC, abstractmethod
from typing import Generator, Dict, Any

from pathlib2 import Path
from psutil import process_iter, Process

from pinecone.core.main import Pinecone
from pinecone.utils.template import render_template


class BaseModule(ABC):
    META = {
        "id": None,
        "name": None,
        "author": None,
        "version": None,
        "description": None,
        "options": None
    }  # type: Dict[str, Any]

    @abstractmethod
    def run(self, args: argparse.Namespace, cmd: Pinecone) -> Any:
        pass

    @abstractmethod
    def stop(self, cmd: Pinecone) -> Any:
        pass


class DaemonBaseModule(BaseModule):
    TMP_FOLDER_PATH = Path(sys.path[0], "tmp").resolve()  # type: Path

    PROCESS_NAME = None  # type: str
    CONFIG_TEMPLATE_PATH = None  # type: Path
    CONFIG_FILENAME = None  # type: str

    @abstractmethod
    def __init__(self):
        self.process = None
        self.config_path = Path(self.TMP_FOLDER_PATH, self.CONFIG_FILENAME)

    def is_running(self) -> bool:
        return self.process is not None and self.process.is_running()

    def stop(self, cmd: Pinecone) -> Any:
        if self.is_running():
            self.process.terminate()
            self.process = None

    @abstractmethod
    def launch(self) -> int:
        pass

    def run(self, args: argparse.Namespace, cmd: Pinecone) -> Any:
        self._term_same_procs()

        render_template(self.CONFIG_TEMPLATE_PATH, self.config_path, args)

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
