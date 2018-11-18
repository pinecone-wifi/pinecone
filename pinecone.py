#!/usr/bin/env python3
import argparse
from urllib.error import URLError

from manuf import manuf

from pinecone.core.config import Config
from pinecone.core.main import Pinecone

parser = argparse.ArgumentParser()
parser.add_argument('-n', dest='numeric_mode', action='store_true', help="don't resolve MAC vendors", default=False)
ops = parser.parse_args()

if __name__ == "__main__":

    if not ops.numeric_mode:
        try:
            Config.MAC_RESOLVER = manuf.MacParser(update=True)
            Config.RESOLVE_MAC = True
        except URLError:
            pass

    Pinecone.reload_modules()
    Pinecone().cmdloop()
