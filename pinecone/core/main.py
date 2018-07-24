import re
import sys
from argparse import ArgumentParser
from importlib import import_module

import cmd2
from pathlib2 import Path


class Pinecone(cmd2.Cmd):
    def __init__(self):
        self.prompt = "(pinecone) "

        self.modules = {}
        self.load_modules()

        super().__init__()

    def load_modules(self):
        modules_it = Path(sys.path[0], "modules").rglob("*.py")

        for py_file_path in modules_it:
            if py_file_path.stem == py_file_path.parent.name:
                module_name = re.search("modules/.*{}".format(py_file_path.stem), py_file_path.as_posix())[0].replace(
                    "/", ".")
                module = import_module(module_name).Module()
                self.modules[module.meta["id"]] = module
                module._update_module_subparsers(Pinecone.module_subparsers)

    module_parser = ArgumentParser(prog="module")
    module_subparsers = module_parser.add_subparsers(title="modules")

    @cmd2.with_argparser(module_parser)
    def do_module(self, args):
        """interact with a specified module."""

        mod_id = getattr(args, "module_id", None)
        func = getattr(args, "func", None)

        if mod_id and func:
            func(self.modules[mod_id], args)
        else:
            self.poutput(str(self.modules))
