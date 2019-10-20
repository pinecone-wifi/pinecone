#!/usr/bin/env python3

from pinecone.core.main import Pinecone

if __name__ == "__main__":
    Pinecone.reload_modules()
    Pinecone().cmdloop()
