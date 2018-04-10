import os
import sys

from .service_set import *
from .client import *

DB_PATH = os.path.abspath(os.path.join(
    os.path.dirname(sys.modules['__main__'].__file__),
    'db',
    'database.sqlite'
))

print("[i] Database file:", DB_PATH)

db.bind(provider='sqlite', filename=DB_PATH, create_db=True)
db.generate_mapping(create_tables=True)

