import argparse

from pony.orm import db_session
from py2neo import Graph, Node, Relationship, Transaction

from pinecone.core.database import BasicServiceSet, to_dict, Client
from pinecone.core.main import Pinecone
from pinecone.core.module import BaseModule


class Module(BaseModule):
    META = {
        "id": "report/db2neo4j",
        "name": "Current recon database to neo4j graph database",
        "author": "Raúl Sampedro (https://github.com/rsrdesarrollo)",
        "version": "1.0.0",
        "description": "Dumps the current recon database to a ne04j graph database.",
        "options": argparse.ArgumentParser(formatter_class=argparse.ArgumentDefaultsHelpFormatter),
        "depends": {}
    }
    META["options"].add_argument(
        "-u", "--uri",
        help="neo4j connection URI",
        default="bolt://neo4j:neo4j@127.0.0.1:7687"
    )

    def run(self, args, cmd):
        driver = Graph(args.uri)

        tx = driver.begin()
        self._create_bss_nodes(tx)
        tx.commit()

        tx = driver.begin()
        self._create_client_nodes(tx)
        tx.commit()

        cmd.pfeedback("[i] Neo4j dump completed.")

    def stop(self, cmd: Pinecone):
        pass

    @db_session
    def _create_bss_nodes(self, tx: Transaction):
        for bss in BasicServiceSet.select():
            bss_node = Node("BSS", **to_dict(bss))
            tx.merge(bss_node, primary_label="BSS", primary_key="bssid")
            if bss.ess is not None:
                ess_node = Node("ESS", essid=bss.ess.ssid)
                tx.merge(ess_node, primary_label="ESS", primary_key="essid")
                announcement = Relationship(bss_node, "ANNOUNCES", ess_node)
                tx.create(announcement)

    @db_session
    def _create_client_nodes(self, tx: Transaction):
        for client in Client.select():
            client_node = Node("Client", **to_dict(client))
            tx.merge(client_node, primary_label="Client", primary_key="mac")

            for connection in client.connections:
                bss_node = Node("BSS", **to_dict(connection.bss))
                tx.merge(bss_node, primary_label="BSS", primary_key="bssid")
                conection_rel = Relationship(client_node, "CONNECTED", bss_node, **to_dict(connection))
                tx.create(conection_rel)

            for probe in client.probe_reqs:
                ess_node = Node("ESS", essid=probe.ess.ssid)
                tx.merge(ess_node, primary_label="ESS", primary_key="essid")
                announcement = Relationship(client_node, "PROBES", ess_node, **to_dict(probe))
                tx.create(announcement)
