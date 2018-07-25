import importlib.util
import re
import sys

import cmd2
from cmd2 import argparse_completer
from pathlib2 import Path


class Pinecone(cmd2.Cmd):
    default_prompt = "(pinecone) "
    prompt_format = "(picone-{}) "
    modules = {}

    def __init__(self):
        self.prompt = self.default_prompt
        self.current_module = None

        super().__init__()

    @classmethod
    def load_modules(cls):
        modules_it = Path(sys.path[0], "modules").rglob("*.py")

        for py_file_path in modules_it:
            if py_file_path.stem == py_file_path.parent.name:
                module_name = re.search("modules/.*{}".format(py_file_path.stem), py_file_path.as_posix())[0].replace(
                    "/", ".")
                module_spec = importlib.util.spec_from_file_location(module_name, py_file_path)
                module = importlib.util.module_from_spec(module_spec)
                module_spec.loader.exec_module(module)
                module_class = module.Module
                cls.modules[module_class.meta["id"]] = module_class()

    use_parser = argparse_completer.ACArgumentParser()
    module_action = use_parser.add_argument("module", type=str, help="module ID")
    setattr(module_action, argparse_completer.ACTION_ARG_CHOICES, modules)

    @cmd2.with_argparser(use_parser)
    def do_use(self, args):
        """interact with a specified module."""

        if args.module in self.modules:
            self.current_module = self.modules[args.module]
            type(self).do_run = cmd2.with_argparser(self.current_module.meta["options"])(type(self)._do_run)
            self.prompt = self.prompt_format.format(args.module.split("/")[-1])

    def _do_run(self, args):
        self.current_module.run(args)

    do_run = _do_run

    def do_stop(self, args):
        pass

    def do_back(self, args):
        type(self).do_run = type(self)._do_run
        self.prompt = self.default_prompt
