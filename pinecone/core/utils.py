import typing

from pyric import pyw


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
