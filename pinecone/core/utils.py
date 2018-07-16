import typing

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
            pyw.down(interface)
            pyw.modeset(interface, "monitor")
            pyw.up(interface)

        return interface


class ScapyUtils:
    @staticmethod
    def process_dot11elts(dot11elts: Dot11Elt) -> typing.Dict[str, typing.Any]:
        dot11elts_info = {
            "ssid": None,
            "channel": None,
            "encryption_types": set(),
        }

        while isinstance(dot11elts, Dot11Elt):
            if dot11elts.ID == 0 and dot11elts.len and dot11elts.len > 0:
                try:
                    dot11elts_info["ssid"] = dot11elts.info.decode()
                except:
                    pass
            elif dot11elts.ID == 3:
                try:
                    dot11elts_info["channel"] = ord(dot11elts.info)
                except:
                    pass
            elif dot11elts.ID == 48:
                dot11elts_info["encryption_types"].add("WPA2")
            elif dot11elts.ID == 221 and dot11elts.info.startswith(b"\x00\x50\xf2\x01\x01\x00"):
                dot11elts_info["encryption_types"].add("WPA")

            dot11elts = dot11elts.payload

        return dot11elts_info