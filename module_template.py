import argparse
from typing import Dict, Any

from pinecone.core.main import Pinecone
from pinecone.core.module import BaseModule


class Module(BaseModule):
    """
    This module serves as an template from which a real module can be built. The name of the class should be 'Module',
    and the class should extend from any of the base abstract classes provided in the pinecone.core.module or
    pinecone.core.script Python's modules. For a working example look any real module, like the 'attack/deauth' one.
    """

    # Module's meta-information.
    META = {
        # ID of the module as it would appear in the directories tree.
        "id": "example/template",
        # Module's short name.
        "name": "Pinecone module template",
        # Module's author.
        "author": "Valentín Blanco (https://github.com/valenbg1)",
        # Module's version.
        "version": "1.0.0",
        # Module's long description.
        "description": "This module serves as an template from which a real module can be built.",
        # Module's options. It can be an argparse.ArgumentParser or a cmd2.argparse_completer.ACArgumentParser for
        # leveraging cmd2's auto-completion.
        "options": argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter),
        # Set of module's dependencies. They can be either Python packages and, in the case of developing a Pinecone
        # extension script, also other modules IDs.
        "depends": {}
    }  # type: Dict[str, Any]
    # Example options added to the argument parser.
    META["options"].add_argument("-s", "--str", help="string option example", default="example")
    META["options"].add_argument("-n", "--number", help="number option example", type=int, default=0)

    def run(self, args: argparse.Namespace, cmd: Pinecone) -> Any:
        """
        Implements the module's main functionality.
        :param args: this method receives the options parsed in this parameter, as an argparse.Namespace instance.
        :param cmd: an instance of Pinecone's main cmd2 object, which can be primarily used for providing feedback to
                    the user.
        :return: this method can return anything.
        """

        cmd.pfeedback("[i] This prints non-essential feedback.")
        cmd.poutput("This prints module's output.")
        cmd.perror("This prints an error.")

    def stop(self, cmd: Pinecone) -> Any:
        """
        Implements the module's stop functionality (for example, in case the module stays running in the background).
        :param cmd: an instance of Pinecone's main cmd2 object, which can be primarily used for providing feedback to
                    the user.
        :return: this method can return anything.
        """

        cmd.poutput("The module correctly stopped!")
