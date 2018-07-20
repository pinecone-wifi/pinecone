import typing
from binascii import unhexlify

from pyric import pyw
from scapy.layers.dot11 import Dot11Elt


class IfaceUtils:
    @staticmethod
    def _get_card(interface: typing.Union[str, pyw.Card]) -> pyw.Card:
        return pyw.getcard(interface) if isinstance(interface, str) else interface

    @staticmethod
    def set_monitor_mode(interface: typing.Union[str, pyw.Card]) -> pyw.Card:
        interface = IfaceUtils._get_card(interface)

        if pyw.modeget(interface) != "monitor":
            if pyw.isup(interface):
                pyw.down(interface)

            pyw.modeset(interface, "monitor")

        if not pyw.isup(interface):
            pyw.up(interface)

        return interface


class ScapyUtils:
    wpa_cipher_type_ids = {
        1: "WEP40",
        2: "TKIP",
        3: "WRAP",
        4: "CCMP-128",
        5: "WEP104",
        8: "GCMP-128",
        9: "GCMP-256",
        10: "CCMP-256"
    }

    wpa_authn_type_ids = {
        1: "MGT",
        2: "PSK",
    }

    wep_authn_type_ids = {
        0: "OPN",
        1: "SKA"
    }

    @staticmethod
    def is_multicast_mac(mac: str) -> bool:
        return (unhexlify(mac[0:2])[0] % 2) != 0

    @staticmethod
    def _process_security_dot11elt(sec_dot11elt: Dot11Elt) -> typing.Dict[str, typing.Any]:
        sec_info = {
            "encryption_type": None,
            "cipher_types": set(),
            "authn_types": set()
        }
        sec_dot11elt_id = sec_dot11elt.sprintf("%ID%")

        if sec_dot11elt_id == "RSNinfo":
            sec_info["encryption_type"] = "WPA2"
            cipher_types_count_offset = 6
        elif sec_dot11elt_id == "vendor":
            sec_info["encryption_type"] = "WPA"
            cipher_types_count_offset = 10
        else:
            return sec_info

        def process_list(offset: int):
            count = int.from_bytes(sec_dot11elt.info[offset:offset + 2], byteorder="little")
            ids_offset = offset + 5
            return set(sec_dot11elt.info[ids_offset:ids_offset + 4 * count:4])

        try:
            sec_info["cipher_types"].update({ScapyUtils.wpa_cipher_type_ids.get(id) for id in
                                             process_list(cipher_types_count_offset)})

            authn_types_count_offset = 8 + len(sec_info["cipher_types"]) * 4
            sec_info["authn_types"].update({ScapyUtils.wpa_authn_type_ids.get(id) for id in
                                            process_list(authn_types_count_offset)})
        except:
            pass

        sec_info["cipher_types"].difference_update({None})
        sec_info["authn_types"].difference_update({None})

        return sec_info

    @staticmethod
    def process_dot11elts(dot11elts: Dot11Elt) -> typing.Dict[str, typing.Any]:
        dot11elts_info = {
            "ssid": None,
            "channel": None,
            "encryption_types": set(),
            "cipher_types": set(),
            "authn_types": set()
        }

        dot11elt = dot11elts

        while isinstance(dot11elt, Dot11Elt):
            dot11elt_id = dot11elt.sprintf("%ID%")

            if dot11elt_id == "SSID" and dot11elt.len is not None and dot11elt.len == 0 and dot11elt.info == b"":
                dot11elts_info["ssid"] = ""
            elif dot11elt_id == "SSID" and dot11elt.len and dot11elt.len > 0:
                try:
                    dot11elts_info["ssid"] = dot11elt.info.decode()
                except:
                    pass
            elif dot11elt_id == "DSset":
                try:
                    dot11elts_info["channel"] = dot11elt.info[0]
                except:
                    pass
            elif dot11elt_id == "RSNinfo" or (
                    dot11elt_id == "vendor" and dot11elt.info.startswith(b"\x00\x50\xf2\x01\x01\x00")):
                sec_dot11elt_info = ScapyUtils._process_security_dot11elt(dot11elt)
                dot11elts_info["encryption_types"].add(sec_dot11elt_info["encryption_type"])
                dot11elts_info["cipher_types"].update(sec_dot11elt_info["cipher_types"])
                dot11elts_info["authn_types"].update(sec_dot11elt_info["authn_types"])

            dot11elt = dot11elt.payload

        return dot11elts_info
