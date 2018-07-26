from abc import ABC, abstractmethod
import argparse

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
