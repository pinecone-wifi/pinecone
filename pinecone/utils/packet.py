from typing import Dict, Any, Set

from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Elt
from scapy.layers.eap import EAPOL

import pinecone.core.database as database

WPA_CIPHER_TYPE_IDS = {
    1: "WEP-40",
    2: "TKIP",
    3: "WRAP",
    4: "CCMP-128",
    5: "WEP-104",
    6: "CMAC",
    8: "GCMP-128",
    9: "GCMP-256",
    10: "CCMP-256",
    11: "GMAC-128",
    12: "GMAC-256",
    13: "CMAC-256"
}

WPA_AUTHN_TYPE_IDS = {
    1: "MGT",
    2: "PSK",
}

WEP_AUTHN_TYPE_IDS = {
    0: "OPN",
    1: "SKA"
}

BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"


# Edited, original source
# https://github.com/secdev/scapy/blob/1fc08e01f9d88c226e6a2132d6dec2a43eb660dd/scapy/contrib/wpa_eapol.py#L24
class WPA_key(Packet):
    name = "WPA_key"
    fields_desc = [ByteField("descriptor_type", 1),

                   # ShortField("key_info", 0),
                   BitField("key_info_reserved", 0, 2),
                   FlagsField("key_info_flags", 0, 8,
                              ["install", "ACK", "MIC", "secure", "error", "request", "encrypted-key-data", "SMK-msg"]),
                   BitField("key_info_index", 0, 2),
                   BitEnumField("key_info_type", 0, 1, ["group", "pairwise"]),
                   BitField("key_info_descriptor_version", 0, 3),

                   LenField("len", None, "H"),
                   StrFixedLenField("replay_counter", "", 8),
                   StrFixedLenField("nonce", "", 32),
                   StrFixedLenField("key_iv", "", 16),
                   StrFixedLenField("wpa_key_rsc", "", 8),
                   StrFixedLenField("wpa_key_id", "", 8),
                   StrFixedLenField("wpa_key_mic", "", 16),
                   LenField("wpa_key_length", None, "H"),
                   StrLenField("wpa_key", "", length_from=lambda pkt: pkt.wpa_key_length)]  # noqa: E501

    def extract_padding(self, s):
        l = self.len
        return s[:l], s[l:]

    def hashret(self):
        return chr(self.type) + self.payload.hashret()

    def answers(self, other):
        if isinstance(other, WPA_key):
            return 1
        return 0


bind_layers(EAPOL, WPA_key, type=3)


# Original source
# https://github.com/secdev/scapy/blob/1fc08e01f9d88c226e6a2132d6dec2a43eb660dd/scapy/layers/dot11.py#L501
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


# Original source
# https://github.com/secdev/scapy/blob/1fc08e01f9d88c226e6a2132d6dec2a43eb660dd/scapy/layers/dot11.py#L483
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


# Original source
# https://github.com/secdev/scapy/blob/1fc08e01f9d88c226e6a2132d6dec2a43eb660dd/scapy/layers/dot11.py#L516
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


# Original source
# https://github.com/secdev/scapy/blob/1fc08e01f9d88c226e6a2132d6dec2a43eb660dd/scapy/layers/dot11.py#L532
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


# Edited, original source
# https://github.com/secdev/scapy/blob/1fc08e01f9d88c226e6a2132d6dec2a43eb660dd/scapy/layers/dot11.py#L578
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


def compare_macs(mac1: str, mac2: str) -> bool:
    return mac2str(mac1) == mac2str(mac2)


def get_flags_set(flags: FlagValue) -> Set[str]:
    return set(str(flags).split("+"))


def get_dot11_ds_bits(packet: Packet) -> Set[str]:
    return get_flags_set(packet[Dot11].FCfield) & {"to-DS", "from-DS"}


def get_dot11_addrs_info(packet: Packet) -> Dict[str, Any]:
    dot11_addrs_info = {
        "da": None,
        "sa": None,
        "bssid": None,
        "ra": None,
        "ta": None,
        "ds_bits": get_dot11_ds_bits(packet)
    }

    dot11_packet = packet[Dot11]

    if not dot11_addrs_info["ds_bits"]:  # no to-DS & no from-DS
        dot11_addrs_info["da"] = dot11_packet.addr1
        dot11_addrs_info["sa"] = dot11_packet.addr2
        dot11_addrs_info["bssid"] = dot11_packet.addr3
    elif dot11_addrs_info["ds_bits"] == {"to-DS"}:
        dot11_addrs_info["bssid"] = dot11_packet.addr1
        dot11_addrs_info["sa"] = dot11_packet.addr2
        dot11_addrs_info["da"] = dot11_packet.addr3
    elif dot11_addrs_info["ds_bits"] == {"from-DS"}:
        dot11_addrs_info["da"] = dot11_packet.addr1
        dot11_addrs_info["bssid"] = dot11_packet.addr2
        dot11_addrs_info["sa"] = dot11_packet.addr3
    else:  # to-DS & from-DS
        dot11_addrs_info["ra"] = dot11_packet.addr1
        dot11_addrs_info["ta"] = dot11_packet.addr2
        dot11_addrs_info["da"] = dot11_packet.addr3
        dot11_addrs_info["sa"] = dot11_packet.addr4

    return dot11_addrs_info


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

        if dot11elts_info["ssid"] is None and dot11elt_id == "SSID" and dot11elt.len is not None:
            if (dot11elt.len == 0 and dot11elt.info == b"") or (
                    dot11elt.len > 0 and all(n == 0 for n in dot11elt.info)):
                dot11elts_info["ssid"] = ""
            elif dot11elt.len > 0:
                try:
                    dot11elts_info["ssid"] = dot11elt.info.decode()
                except:
                    pass
        elif dot11elts_info["channel"] is None and dot11elt_id == "DSset":
            try:
                dot11elts_info["channel"] = dot11elt.info[0]
            except:
                pass
        elif ("WPA2" not in dot11elts_info["encryption_types"] and dot11elt_id == "RSNinfo") or ("WPA" not in
                dot11elts_info["encryption_types"] and dot11elt_id == "vendor" and
                dot11elt.info.startswith(b"\x00\x50\xf2\x01\x01\x00")):
            sec_dot11elt_info = _process_security_dot11elt(dot11elt)
            dot11elts_info["encryption_types"].add(sec_dot11elt_info["encryption_type"])
            dot11elts_info["cipher_types"].update(sec_dot11elt_info["cipher_types"])
            dot11elts_info["authn_types"].update(sec_dot11elt_info["authn_types"])

        dot11elt = dot11elt.payload

    return dot11elts_info
