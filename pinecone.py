#!/usr/bin/env python3

from pinecone.core.main import Pinecone

if __name__ == "__main__":
    Pinecone.load_modules()
    Pinecone().cmdloop()
