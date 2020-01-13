import argparse

from pony.orm import db_session
from py2neo import Graph, Relationship, Transaction

from pinecone.core.database import BasicServiceSet, Client
from pinecone.core.database import to_dict
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
    META["options"].add_argument(
        "-s", "--skip-empty-clients",
        help="don't create clients without any connection/probe",
        default=False,
        required=False,
        action="store_true"
    )
    META["options"].add_argument(
        "-a", "--aggregate-probes",
        help="aggregate clients with same probes in one node",
        default=False,
        required=False,
        action="store_true"
    )

    def run(self, args, cmd):
        self.cmd = cmd

        driver = Graph(args.uri)

        tx = driver.begin()
        self._create_bss_nodes(tx)
        tx.commit()

        tx = driver.begin()
        if args.aggregate_probes:
            self._create_client_aggregated_nodes(tx, args.skip_empty_clients)
        else:
            self._create_client_nodes(tx, args.skip_empty_clients)
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
    def _create_client_nodes(self, tx: Transaction, skipt_empty: bool):
        for client in Client.select():
            if skipt_empty and not client.connections and not client.probe_reqs:
                continue

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

    @db_session
    def _create_client_aggregated_nodes(self, tx: Transaction, skipt_empty: bool):
            agg_nodes = dict()

            for client in Client.select():
                if skipt_empty and not client.connections and not client.probe_reqs:
                    continue

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

                probes = frozenset(probe.ess for probe in client.probe_reqs)
                agg_nodes.get(probes, list()).append(client)

            for probe_ssids, clients in agg_nodes.items():

                group_id = hash(probe_ssids)

                self.cmd.pfeedback("[i] Aggregating {} clients probing for: {}".format(
                    len(clients),
                    ", ".join(probe_ssids)
                ))

                client_data = {client.mac: True for client in clients}
                client_node = tx.evaluate(
                    "MERGE (_:Client {group_id:{group_id}}) SET _ += {client} RETURN _",
                    client=client_data,
                    group_id=group_id
                )

                for probe_ssid in probe_ssids:
                    ess_node = tx.evaluate(
                        "MERGE (_:ESS {ssid:{ssid}}) RETURN _",
                        ess=ess_data,
                        ssid=probe_ssid
                    )

                    announcement = Relationship(client_node, "PROBES", ess_node)
                    tx.create(announcement)
