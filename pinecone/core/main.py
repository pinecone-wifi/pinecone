from argparse import ArgumentParser
from pathlib2 import Path
from importlib import import_module
import re
import sys

import cmd2


class Pinecone(cmd2.Cmd):
    def __init__(self):
        self.prompt = "(pinecone) "

        self.loaded_modules = {}
        self.load_modules()

        super().__init__()

    def load_modules(self):
        modules_it = Path(sys.path[0], "modules").rglob("*.py")

        for py_file_path in modules_it:
            if py_file_path.stem == py_file_path.parent.name:
                module_name = re.search("modules/.*{}".format(py_file_path.stem), py_file_path.parent.as_posix())[0]
                module = import_module("{}.{}".format(module_name.replace("/", "."), py_file_path.stem)).Module()
                self.loaded_modules[module_name] = module
                module._update_modules_subparsers(Pinecone.use_modules_subparsers)

    use_parser = ArgumentParser()
    use_modules_subparsers = use_parser.add_subparsers(title="modules")

    @cmd2.with_argparser(use_parser)
    def do_use(self, args):
        """Interact with a specified module."""

        mod_id = getattr(args, "mod_id", None)
        func = getattr(args, "func", None)

        print(mod_id, func)

        if mod_id and func :
            func(self.loaded_modules[mod_id], args)
        else:
            self.poutput(str(self.loaded_modules))
