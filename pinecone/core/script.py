from abc import abstractmethod
from pathlib import Path

from pinecone.core.main import TMP_FOLDER_PATH
from pinecone.core.module import BaseModule
from pinecone.utils.template import render_template


class BaseScript(BaseModule):
    START_SCRIPT_TEMPLATE_PATH: Path = None
    START_SCRIPT_FILENAME: str = None

    STOP_SCRIPT_PATH: Path = None

    @abstractmethod
    def __init__(self):
        self.start_script_path = Path(TMP_FOLDER_PATH, self.START_SCRIPT_FILENAME)

    def run(self, args, cmd):
        render_template(self.START_SCRIPT_TEMPLATE_PATH, self.start_script_path, args)
        cmd.do_back()
        cmd.do_run_script(self.start_script_path)
        cmd.do_back()
        cmd.do_use([self.META["id"]])

    def stop(self, cmd):
        cmd.do_back()
        cmd.do_run_script(self.STOP_SCRIPT_PATH)
        cmd.do_back()
        cmd.do_use([self.META["id"]])
