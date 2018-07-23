from typing import Union

from pyric import pyw


def _get_card(interface: Union[str, pyw.Card]) -> pyw.Card:
    return pyw.getcard(interface) if isinstance(interface, str) else interface


def set_monitor_mode(interface: Union[str, pyw.Card]) -> pyw.Card:
    interface = _get_card(interface)

    if pyw.modeget(interface) != "monitor":
        if pyw.isup(interface):
            pyw.down(interface)

        pyw.modeset(interface, "monitor")

    if not pyw.isup(interface):
        pyw.up(interface)

    return interface
