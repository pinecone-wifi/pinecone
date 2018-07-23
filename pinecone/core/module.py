from abc import ABC, abstractmethod


class Module(ABC):
    @abstractmethod
    def run(self):
        pass

    @abstractmethod
    def stop(self):
        pass
