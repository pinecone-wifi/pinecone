from argparse import ArgumentParser

import cmd2


class Pinecone(cmd2.Cmd):
    def __init__(self):
        self.prompt = "(pinecone) "

        super().__init__()

    use_parser = ArgumentParser()
    use_parser.add_argument("module", help="Module to use.", type=str)

    @cmd2.with_argparser(use_parser)
    def do_use(self, args):
        """Interact with a specified module."""

        self.poutput(args)
