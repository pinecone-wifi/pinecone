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
    def _update_module_subparsers(cls, modules_subparsers):
        module_id = cls.meta["id"]

        module_parser = modules_subparsers.add_parser(module_id)
        commands_parser = module_parser.add_subparsers(title="commands")
        run_parser = commands_parser.add_parser("run")
        run_parser.set_defaults(module_id=module_id, func=cls.run)
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
