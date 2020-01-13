#!/usr/bin/env python3

import argparse
from pinecone.core.database import init_database
from pinecone.core.main import Pinecone


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--database', required=False)
    args = parser.parse_args()

    init_database(args)

    Pinecone.reload_modules()
    Pinecone().cmdloop()
