from sys import modules

from pathlib2 import Path

from pinecone.core.database import db
from pinecone.model.client import Client
from pinecone.model.network import ProbeReq, Connection
from pinecone.model.service_set import BasicServiceSet, ExtendedServiceSet

DB_PATH = str(Path(Path(modules["__main__"].__file__).parent, "db", "database.sqlite").resolve())
Path(DB_PATH).parent.mkdir(exist_ok=True)

print("[i] Database file:", DB_PATH)

db.bind(provider="sqlite", filename=DB_PATH, create_db=True)
db.generate_mapping(create_tables=True)
