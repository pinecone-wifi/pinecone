import argparse

from pony.orm import db_session
from py2neo import Graph, Relationship, Transaction

from pinecone.core.database import to_dict, BasicServiceSet, Client
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
            bss_data = to_dict(bss)
            bss_node = tx.evaluate(
                "MERGE (_:BSS {bssid:{bssid}}) SET _ += {bss} RETURN _",
                bss=bss_data,
                bssid=bss.bssid
            )

            if bss.ess is not None:
                ess_data = to_dict(bss.ess)

                ess_node = tx.evaluate(
                    "MERGE (_:ESS {ssid:{ssid}}) SET _ += {ess} RETURN _",
                    ess=ess_data,
                    ssid=bss.ess.ssid
                )

                announcement = Relationship(bss_node, "ANNOUNCES", ess_node)
                tx.create(announcement)

    @db_session
    def _create_client_nodes(self, tx: Transaction):
        for client in Client.select():
            client_data = to_dict(client)
            client_node = tx.evaluate(
                "MERGE (_:Client {mac:{mac}}) SET _ += {client} RETURN _",
                client=client_data,
                mac=client.mac
            )

            for connection in client.connections:
                bss_data = to_dict(connection.bss)
                bss_node = tx.evaluate(
                    "MERGE (_:BSS {bssid:{bssid}}) SET _ += {bss} RETURN _",
                    bss=bss_data,
                    bssid=connection.bss.bssid
                )

                connection_rel = Relationship(client_node, "CONNECTED", bss_node, **to_dict(connection))
                tx.create(connection_rel)

            for probe in client.probe_reqs:
                ess_data = to_dict(probe.ess)

                ess_node = tx.evaluate(
                    "MERGE (_:ESS {ssid:{ssid}}) SET _ += {ess} RETURN _",
                    ess=ess_data,
                    ssid=probe.ess.ssid
                )

                announcement = Relationship(client_node, "PROBES", ess_node, **to_dict(probe))
                tx.create(announcement)
