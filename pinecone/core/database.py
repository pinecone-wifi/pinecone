from sys import modules
from datetime import datetime

from pathlib2 import Path
from pony.orm import *

ENCRYPTION_TYPES = {"OPN", "WEP", "WPA", "WPA2"}
CIPHER_TYPES = {"WEP", "TKIP", "CCMP"}
AUTHN_TYPES = {"PSK", "MGT"}

db = Database()


class BasicServiceSet(db.Entity):
    bssid = PrimaryKey(str, max_len=18)
    channel = Required(int)
    encryption = Required(str, py_check=lambda t: t in ENCRYPTION_TYPES)
    cipher = Optional(str, py_check=lambda t: t in CIPHER_TYPES)
    authn = Optional(str, py_check=lambda t: t in AUTHN_TYPES)
    last_seen = Required(datetime)
    ess = Optional("ExtendedServiceSet", reverse="bssets")
    hides_ssid = Required(bool)
    #band
    #channel_width
    connections = Set("Connection")

    def __str__(self):
        ess_info = str(self.ess) if self.ess is not None else ""

        return "BSSID: {}, channel: {}, encryption: {}, last seen: {}, ESS: ({}), hides SSID: {}".format(
            self.bssid, self.channel, self.encryption,
            self.last_seen, ess_info, self.hides_ssid)


class ExtendedServiceSet(db.Entity):
    ssid = PrimaryKey(str, max_len=32)
    bssets = Set(BasicServiceSet, reverse="ess")
    probes_recvd = Set("ProbeReq")

    def __str__(self):
        return "SSID: \"{}\"".format(self.ssid)


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

    def __str__(self):
        return "Client: ({}), ESS: ({}), last seen: {}".format(self.client, self.ess, self.last_seen)


class Client(db.Entity):
    mac = PrimaryKey(str, max_len=18)
    probe_reqs = Set(ProbeReq, reverse="client")
    connections = Set(Connection, reverse="client")

    def __str__(self):
        return "MAC: {}".format(self.mac)


DB_PATH = str(Path(Path(modules["__main__"].__file__).parent, "db", "database.sqlite").resolve())
Path(DB_PATH).parent.mkdir(exist_ok=True)

print("[i] Database file: ", DB_PATH)

db.bind(provider="sqlite", filename=DB_PATH, create_db=True)
db.generate_mapping(create_tables=True)
