from abc import ABC, abstractmethod


class BaseModule(ABC):
    meta = {
        "id": None,
        "name": None,
        "author": None,
        "version": None,
        "description": None
    }

    @classmethod
    def _update_modules_subparsers(cls, modules_subparsers):
        mod_id = cls.meta["id"]

        mod_parser = modules_subparsers.add_parser(mod_id)
        commands_parser = mod_parser.add_subparsers(title="Commands")
        run_parser = commands_parser.add_parser("run")
        run_parser.set_defaults(mod_id=mod_id, func=cls.run)
        cls.set_run_parser(run_parser)

    @classmethod
    @abstractmethod
    def set_run_parser(cls, run_parser):
        pass

    @abstractmethod
    def run(self, args):
        pass

    @abstractmethod
    def stop(self):
        pass
