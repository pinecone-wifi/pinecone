from sys import modules
from datetime import datetime

from pathlib2 import Path
from pony.orm import *

ENCRYPTION_TYPES = {"OPN", "WEP", "WPA", "WPA2"}
db = Database()


class BasicServiceSet(db.Entity):
    bssid = PrimaryKey(str, max_len=18)
    channel = Required(int)
    encryption = Required(str, py_check=lambda x: x in ENCRYPTION_TYPES)
    last_seen = Required(datetime)
    ess = Optional("ExtendedServiceSet", reverse="bssets")
    #band
    #channel_width
    connections = Set("Connection")


class ExtendedServiceSet(db.Entity):
    ssid = PrimaryKey(str, max_len=32)
    bssets = Set(BasicServiceSet, reverse="ess")
    probes_recvd = Set("ProbeReq")


class Connection(db.Entity):
    client = Required("Client")
    bss = Required(BasicServiceSet)
    last_seen = Required(datetime)

    PrimaryKey(client, bss)


class ProbeReq(db.Entity):
    client = Required("Client")
    ess = Required(ExtendedServiceSet)
    last_seen = Required(datetime)

    PrimaryKey(client, ess)


class Client(db.Entity):
    mac = PrimaryKey(str, max_len=18)
    probe_reqs = Set(ProbeReq, reverse="client")
    connections = Set(Connection, reverse="client")


DB_PATH = str(Path(Path(modules["__main__"].__file__).parent, "db", "database.sqlite").resolve())
Path(DB_PATH).parent.mkdir(exist_ok=True)

print("[i] Database file:", DB_PATH)

db.bind(provider="sqlite", filename=DB_PATH, create_db=True)
db.generate_mapping(create_tables=True)
