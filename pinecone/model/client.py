from pinecone.core.database import db
from pony.orm import *

from pinecone.model import ExtendedServiceSet

class Client(db.Entity):
    mac = PrimaryKey(str, max_len=18)
    probes = Set(ExtendedServiceSet, reverse='clients')