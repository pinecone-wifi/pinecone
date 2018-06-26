from pathlib import Path
from sys import modules

from .service_set import *
from .client import *

DB_PATH = str(Path(Path(modules["__main__"].__file__).parent, "db", "database.sqlite").resolve())
Path(DB_PATH).parent.mkdir(exist_ok=True)

print("[i] Database file:", DB_PATH)

db.bind(provider="sqlite", filename=DB_PATH, create_db=True)
db.generate_mapping(create_tables=True)
