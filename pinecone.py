#!/usr/bin/env python3
import argparse
from urllib.error import URLError

from pinecone.core.main import Pinecone

parser = argparse.ArgumentParser()
#parser.add_argument('-n', dest='numeric_mode', action='store_true', help="don't resolve MAC vendors", default=False)
ops = parser.parse_args()

if __name__ == "__main__":
    Pinecone.reload_modules()
    Pinecone().cmdloop()
