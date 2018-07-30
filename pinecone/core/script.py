from pinecone.core.module import BaseModule


class Script(BaseModule):
    META = dict(BaseModule.META)
    META["depends"] = None
