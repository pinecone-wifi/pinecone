import json
from pathlib import Path

from pony.orm import db_session

from pinecone.core.database import BasicServiceSet, ExtendedServiceSet, Connection, ProbeReq, Client
from pinecone.core.module import BaseModule
from pinecone.core.options import Option, OptionDict


class Module(BaseModule):
    META = {
        "id": "report/db2json",
        "name": "Current recon database to JSON module",
        "author": "Valentín Blanco (https://github.com/valenbg1)",
        "version": "1.0.0",
        "description": "Prints the current recon database to a JSON file.",
        "options": OptionDict(),
        "depends": {}
    }
    META["options"].add(Option("WRITE", "recon-db.json", True, "JSON output file"))

    @db_session
    def run(self, opts, cmd):
        opts = opts.get_opts_namespace()
        json_dict = {
            "basic_service_sets": [],
            "extended_service_sets": [],
            "connections": [],
            "probe_reqs": [],
            "clients": []
        }

        for bss in BasicServiceSet.select():
            if bss.ess is None:
                ess = None
            else:
                ess = {
                    "ssid": bss.ess.ssid
                }

            json_dict["basic_service_sets"].append({
                "bssid": bss.bssid,
                "channel": bss.channel,
                "encryption_types": bss.encryption_types,
                "cipher_types": bss.cipher_types,
                "authn_types": bss.authn_types,
                "last_seen": str(bss.last_seen),
                "ess": ess,
                "hides_ssid": bss.hides_ssid
            })

        for ess in ExtendedServiceSet.select():
            json_dict["extended_service_sets"].append({
                "ssid": ess.ssid
            })

        for connection in Connection.select():
            json_dict["connections"].append({
                "client": {
                    "mac": connection.client.mac
                },
                "bss": {
                    "bssid": connection.bss.bssid
                },
                "last_seen": str(connection.last_seen)
            })

        for probe_req in ProbeReq.select():
            json_dict["probe_reqs"].append({
                "client": {
                    "mac": probe_req.client.mac
                },
                "ess": {
                    "ssid": probe_req.ess.ssid
                },
                "last_seen": str(probe_req.last_seen)
            })

        for client in Client.select():
            json_dict["clients"].append({
                "mac": client.mac
            })

        Path(opts.write).write_text(json.dumps(json_dict, indent=4))

    def stop(self, cmd):
        pass
