from abc import abstractmethod

from pathlib2 import Path

from pinecone.core.main import TMP_FOLDER_PATH
from pinecone.core.module import BaseModule
from pinecone.utils.template import render_template


class BaseScript(BaseModule):
    START_SCRIPT_TEMPLATE_PATH = None  # type: Path
    START_SCRIPT_FILENAME = None  # type: str

    STOP_SCRIPT_PATH = None  # type: Path

    @abstractmethod
    def __init__(self):
        self.start_script_path = Path(TMP_FOLDER_PATH, self.START_SCRIPT_FILENAME)

    def run(self, args, cmd):
        render_template(self.START_SCRIPT_TEMPLATE_PATH, self.start_script_path, args)
        cmd.do_back()
        cmd.do_load(str(self.start_script_path))
        cmd.runcmds_plus_hooks([])
        cmd.do_back()
        cmd.do_use(self.META["id"])

    def stop(self, cmd):
        cmd.do_back()
        cmd.do_load(str(self.STOP_SCRIPT_PATH))
        cmd.runcmds_plus_hooks([])
        cmd.do_back()
        cmd.do_use(self.META["id"])
