import sys
from datetime import datetime

from pathlib2 import Path
from pony.orm import *

ENCRYPTION_TYPES = {"OPN", "WEP", "WPA", "WPA2"}
CIPHER_TYPES = {"WEP", "WEP-40", "TKIP", "WRAP", "CCMP-128", "WEP-104", "CMAC", "GCMP-128", "GCMP-256", "CCMP-256",
                "GMAC-128", "GMAC-256", "CMAC-256"}
AUTHN_TYPES = {"OPN", "SKA", "PSK", "MGT"}

db = Database()


class BasicServiceSet(db.Entity):
    """BSS model class:
        Represents an Access Point, normally identified by a BSSID (which is a MAC Address)
    """
    bssid = PrimaryKey(str, max_len=18)
    channel = Optional(int)
    encryption_types = Optional(str)
    cipher_types = Optional(str)
    authn_types = Optional(str)
    last_seen = Required(datetime)
    ess = Optional("ExtendedServiceSet")
    hides_ssid = Optional(bool)
    # band
    # channel_width
    connections = Set("Connection")

    def __str__(self):
        ess_info = str(self.ess) if self.ess is not None else ""

        return "BSSID: {}, channel: {}, encryption types: ({}), cipher types: ({}), authn types: ({}), last seen: " \
               "{}, ESS: ({}), hides SSID: {}".format(self.bssid, self.channel, self.encryption_types,
                                                      self.cipher_types, self.authn_types, self.last_seen, ess_info,
                                                      self.hides_ssid)


class ExtendedServiceSet(db.Entity):
    """ESS model class:
        Represents a set of BSS group by the same network name (SSID)
    """
    ssid = PrimaryKey(str, max_len=32)
    bssets = Set(BasicServiceSet)
    probes_recvd = Set("ProbeReq")

    def __str__(self):
        return "SSID: \"{}\"".format(self.ssid)


class Connection(db.Entity):
    """Connection model class:
        Represents the presence of an stabilised relationship between a Client and a BSS (AP)
    """
    client = Required("Client")
    bss = Required(BasicServiceSet)
    last_seen = Required(datetime)

    PrimaryKey(client, bss)

    def __str__(self):
        return "Client: ({}), BSS: ({}), last seen: {}".format(self.client, self.bss, self.last_seen)


class ProbeReq(db.Entity):
    """Probe Request model class:
        Represents the presence of a Probe Request frame from an specific client
    """
    client = Required("Client")
    ess = Required(ExtendedServiceSet)
    last_seen = Required(datetime)

    PrimaryKey(client, ess)

    def __str__(self):
        return "Client: ({}), ESS: ({}), last seen: {}".format(self.client, self.ess, self.last_seen)


class Client(db.Entity):
    """Client model class:
        Represents any WiFi client
    """
    mac = PrimaryKey(str, max_len=18)
    probe_reqs = Set(ProbeReq)
    connections = Set(Connection)

    def __str__(self):
        return "MAC: {}".format(self.mac)


DB_PATH = str(Path(sys.path[0], "db", "database.sqlite").resolve())
Path(DB_PATH).parent.mkdir(exist_ok=True)

print("[i] Database file:", DB_PATH)

db.bind(provider="sqlite", filename=DB_PATH, create_db=True)
db.generate_mapping(create_tables=True)
