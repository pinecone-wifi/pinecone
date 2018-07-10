#!/usr/bin/env python3

import signal
from argparse import ArgumentParser

from pyric import pyw
from scapy.layers.dot11 import *

from pinecone.core.utils import IfaceUtils
from pinecone.model import *

bssid_cache = set()


@db_session
def handle_beacon(pkt):
    bssid = pkt[Dot11].addr3

    if bssid in bssid_cache:
        return

    bssid_cache.add(bssid)

    p = pkt[Dot11Elt]
    cap = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}").split('+')
    ssid, channel = None, None
    crypto = set()
    while isinstance(p, Dot11Elt):
        if p.ID == 0:
            ssid = p.info.decode()
        elif p.ID == 3:
            channel = ord(p.info)
        elif p.ID == 48:
            crypto.add("WPA2")
        elif p.ID == 221 and p.info.startswith(b"\x00P\xf2\x01\x01\x00"):
            crypto.add("WPA")
        p = p.payload
    if not crypto:
        if "privacy" in cap:
            crypto.add("WEP")
        else:
            crypto.add("OPN")

    enc = crypto.pop()
    try:
        ess = ExtendedServiceSet(ssid=ssid)
        commit()
    except:
        pass

    try:
        # TODO: fix multiple encryptions APs
        ess = ExtendedServiceSet[ssid]
        BasicServiceSet(bssid=bssid, channel=channel, enc=enc, ess=ess)
        commit()
    except:
        pass

    print("[*] [ch:{}] {} [{}], {}".format(channel, ssid, bssid, enc))


def handle_packet(packet):
    if packet.haslayer(Dot11ProbeReq) or packet.haslayer(Dot11ProbeResp) or packet.haslayer(Dot11AssoReq):
        pass
    elif packet.haslayer(Dot11Beacon):
        handle_beacon(packet)


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument("-i", "--iface", help="interface", default="wlan0", type=str)
    ops = parser.parse_args()

    # chann_hops = (1, 6, 11, 14, 2, 7, 12, 3, 8, 13, 4, 9, 5, 10)
    chann_hops = (1, 6, 11, 2, 7, 12, 3, 8, 13, 4, 9, 5, 10)

    running = True


    def sig_exit_handle(signal, frame):
        global running
        running = False

        print("[i] Exiting...")


    signal.signal(signal.SIGTERM, sig_exit_handle)
    signal.signal(signal.SIGINT, sig_exit_handle)

    while running:
        mon_iface = IfaceUtils.set_monitor_mode(ops.iface)

        try:
            for channel in chann_hops:
                pyw.chset(mon_iface, channel)

                sniff(iface=ops.iface, prn=handle_packet, timeout=3, store=False)
                if not running: break
        except KeyboardInterrupt:
            pass
