from datetime import datetime

from pony.orm import *

from pinecone.core.database import db

ENCRYPTION_TYPES = {"OPN", "WEP", "WPA", "WPA2"}


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
