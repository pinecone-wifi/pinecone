from datetime import datetime

from pony.orm import *

from pinecone.core.database import db
from .service_set import BasicServiceSet, ExtendedServiceSet


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
