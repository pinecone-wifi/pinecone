from pinecone.core.database import db
from pony.orm import *

ENC_TYPES = {'OPN', 'WEP', 'WPA', 'WPA2'}


class BasicServiceSet(db.Entity):
    bssid = PrimaryKey(str, max_len=18)
    channel = Required(int)
    enc = Required(str, py_check=lambda x: x in ENC_TYPES)
    ess = Required('ExtendedServiceSet', reverse='bss')


class ExtendedServiceSet(db.Entity):
    ssid = PrimaryKey(str, max_len=32)
    bss = Set(BasicServiceSet, reverse='ess')
    clients = Set('Client', reverse='probes')
