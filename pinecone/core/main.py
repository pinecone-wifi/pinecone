import importlib.util
import re
import sys

import cmd2
from cmd2 import argparse_completer
from pathlib2 import Path


class Pinecone(cmd2.Cmd):
    DEFAULT_PROMPT = "pinecone > "
    PROMPT_FORMAT = "picone {}({}) > "
    modules = {}

    def __init__(self):
        self.prompt = self.DEFAULT_PROMPT
        self.current_module = None

        super().__init__()

    @classmethod
    def reload_modules(cls):
        cls.modules.clear()
        modules_it = Path(sys.path[0], "modules").rglob("*.py")

        for py_file_path in modules_it:
            if py_file_path.stem == py_file_path.parent.name:
                module_name = "pinecone.{}".format(
                    re.search("modules/.*{}".format(py_file_path.stem), py_file_path.parent.as_posix()).group().replace(
                        "/", "."))
                module_spec = importlib.util.spec_from_file_location(module_name, str(py_file_path))
                module = importlib.util.module_from_spec(module_spec)
                module_spec.loader.exec_module(module)
                module_class = module.Module
                cls.modules[module_class.META["id"]] = module_class()

    use_parser = argparse_completer.ACArgumentParser()
    use_module_action = use_parser.add_argument("module", type=str, help="module ID")
    setattr(use_module_action, argparse_completer.ACTION_ARG_CHOICES, modules)

    @cmd2.with_argparser(use_parser)
    def do_use(self, args):
        """interact with a specified module."""

        if args.module in self.modules:
            self.current_module = self.modules[args.module]
            type(self).do_run = cmd2.with_argparser(self.current_module.META["options"])(type(self)._do_run)
            self.current_module.META["options"].prog = "run"
            self.prompt = self.PROMPT_FORMAT.format("module", args.module.replace("modules/", ""))

    def _do_run(self, args):
        self.current_module.run(args, self)

    do_run = _do_run

    def do_stop(self, args):
        self.current_module.stop(self)

    def do_back(self, args):
        type(self).do_run = type(self)._do_run
        self.prompt = self.DEFAULT_PROMPT
