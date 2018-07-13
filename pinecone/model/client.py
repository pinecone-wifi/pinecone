from pony.orm import *

from pinecone.core.database import db
from .network import ProbeReq, Connection


class Client(db.Entity):
    mac = PrimaryKey(str, max_len=18)
    probe_reqs = Set(ProbeReq, reverse="client")
    connections = Set(Connection, reverse="client")
