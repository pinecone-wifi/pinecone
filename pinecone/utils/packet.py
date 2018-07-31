from typing import Dict, Any

from scapy.all import *
from scapy.layers.dot11 import Dot11Elt

import pinecone.core.database as database

WPA_CIPHER_TYPE_IDS = {
    1: "WEP-40",
    2: "TKIP",
    3: "WRAP",
    4: "CCMP-128",
    5: "WEP-104",
    8: "GCMP-128",
    9: "GCMP-256",
    10: "CCMP-256"
}

WPA_AUTHN_TYPE_IDS = {
    1: "MGT",
    2: "PSK",
}

WEP_AUTHN_TYPE_IDS = {
    0: "OPN",
    1: "SKA"
}


# Original source https://github.com/secdev/scapy/blob/1fc08e01f9d88c226e6a2132d6dec2a43eb660dd/scapy/layers/dot11.py#L501
class AKMSuite(Packet):
    name = "AKM suite"
    fields_desc = [
        X3BytesField("oui", 0x000fac),
        ByteEnumField("suite", 0x01, {
            0x00: "Reserved",
            0x01: "IEEE 802.1X / PMKSA caching",
            0x02: "PSK"
        })
    ]

    def extract_padding(self, s):
        return "", s


# Original source https://github.com/secdev/scapy/blob/1fc08e01f9d88c226e6a2132d6dec2a43eb660dd/scapy/layers/dot11.py#L483
class RSNCipherSuite(Packet):
    name = "Cipher suite"
    fields_desc = [
        X3BytesField("oui", 0x000fac),
        ByteEnumField("cipher", 0x04, {
            0x00: "Use group cipher suite",
            0x01: "WEP-40",
            0x02: "TKIP",
            0x03: "Reserved",
            0x04: "CCMP",
            0x05: "WEP-104"
        })
    ]

    def extract_padding(self, s):
        return "", s


# Original source https://github.com/secdev/scapy/blob/1fc08e01f9d88c226e6a2132d6dec2a43eb660dd/scapy/layers/dot11.py#L516
class PMKIDListPacket(Packet):
    name = "PMKIDs"
    fields_desc = [
        LEFieldLenField("nb_pmkids", 0, count_of="pmk_id_list"),
        FieldListField(
            "pmkid_list",
            None,
            XStrFixedLenField("", "", length=16),
            count_from=lambda pkt: pkt.nb_pmkids
        )
    ]

    def extract_padding(self, s):
        return "", s


# Original source https://github.com/secdev/scapy/blob/1fc08e01f9d88c226e6a2132d6dec2a43eb660dd/scapy/layers/dot11.py#L532
class Dot11EltRSN(Dot11Elt):
    name = "RSN information"
    fields_desc = [
        ByteField("ID", 48),
        ByteField("len", None),
        LEShortField("version", 1),
        PacketField("group_cipher_suite", RSNCipherSuite(), RSNCipherSuite),
        LEFieldLenField(
            "nb_pairwise_cipher_suites",
            1,
            count_of="pairwise_cipher_suites"
        ),
        PacketListField(
            "pairwise_cipher_suites",
            [RSNCipherSuite()],
            RSNCipherSuite,
            count_from=lambda p: p.nb_pairwise_cipher_suites
        ),
        LEFieldLenField(
            "nb_akm_suites",
            1,
            count_of="akm_suites"
        ),
        PacketListField(
            "akm_suites",
            [AKMSuite()],
            AKMSuite,
            count_from=lambda p: p.nb_akm_suites
        ),
        BitField("pre_auth", 0, 1),
        BitField("no_pairwise", 0, 1),
        BitField("ptksa_replay_counter", 0, 2),
        BitField("gtksa_replay_counter", 0, 2),
        BitField("mfp_required", 0, 1),
        BitField("mfp_capable", 0, 1),
        BitField("reserved", 0, 8),
        ConditionalField(
            PacketField("pmkids", None, PMKIDListPacket),
            lambda pkt: (
                0 if pkt.len is None else
                pkt.len - (12 + (pkt.nb_pairwise_cipher_suites * 4) +
                           (pkt.nb_akm_suites * 4)) >= 18)
        )
    ]


# Edited, original source https://github.com/secdev/scapy/blob/1fc08e01f9d88c226e6a2132d6dec2a43eb660dd/scapy/layers/dot11.py#L578
class Dot11EltMicrosoftWPA(Dot11Elt):
    name = "Microsoft WPA"
    fields_desc = [
        ByteField("ID", 221),
        ByteField("len", None),
        X3BytesField("oui", 0x0050f2),
        XByteField("type", 0x01),
        LEShortField("version", 1),
        PacketField("group_cipher_suite", RSNCipherSuite(), RSNCipherSuite),
        LEFieldLenField(
            "nb_pairwise_cipher_suites",
            1,
            count_of="pairwise_cipher_suites"
        ),
        PacketListField(
            "pairwise_cipher_suites",
            [RSNCipherSuite()],
            RSNCipherSuite,
            count_from=lambda p: p.nb_pairwise_cipher_suites
        ),
        LEFieldLenField(
            "nb_akm_suites",
            1,
            count_of="akm_suites"
        ),
        PacketListField(
            "akm_suites",
            AKMSuite(),
            AKMSuite,
            count_from=lambda p: p.nb_akm_suites
        )
    ]


def is_multicast_mac(mac: str) -> bool:
    return (mac2str(mac)[0] % 2) != 0


def _process_security_dot11elt(sec_dot11elt: Dot11Elt) -> Dict[str, Any]:
    sec_info = {
        "encryption_type": None,
        "cipher_types": set(),
        "authn_types": set()
    }
    sec_dot11elt_id = sec_dot11elt.sprintf("%ID%")

    if sec_dot11elt_id == "RSNinfo":
        sec_info["encryption_type"] = "WPA2"
        sec_dot11elt = Dot11EltRSN(sec_dot11elt)
    elif sec_dot11elt_id == "vendor":
        sec_info["encryption_type"] = "WPA"
        sec_dot11elt = Dot11EltMicrosoftWPA(sec_dot11elt)

    sec_info["cipher_types"].update({WPA_CIPHER_TYPE_IDS.get(c.cipher) for c in sec_dot11elt.pairwise_cipher_suites})
    sec_info["cipher_types"].intersection_update(database.CIPHER_TYPES)

    sec_info["authn_types"].update({WPA_AUTHN_TYPE_IDS.get(s.suite) for s in sec_dot11elt.akm_suites})
    sec_info["authn_types"].intersection_update(database.AUTHN_TYPES)

    return sec_info


def process_dot11elts(dot11elts: Dot11Elt) -> Dict[str, Any]:
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
            sec_dot11elt_info = _process_security_dot11elt(dot11elt)
            dot11elts_info["encryption_types"].add(sec_dot11elt_info["encryption_type"])
            dot11elts_info["cipher_types"].update(sec_dot11elt_info["cipher_types"])
            dot11elts_info["authn_types"].update(sec_dot11elt_info["authn_types"])

        dot11elt = dot11elt.payload

    return dot11elts_info
