from abc import ABC, abstractmethod


class BaseModule(ABC):
    meta = {
        "id": None,
        "name": None,
        "author": None,
        "version": None,
        "description": None,
        "options": None
    }

    @abstractmethod
    def run(self, args):
        pass

    @abstractmethod
    def stop(self):
        pass
