from pcap.constants.IEEE802_Numbers import EtherTypes
from pcap.constants.IPProto_Numbers import IPProto
from pcap.constants.PcapLinkType import PcapLinkType
from pcap.dissectors.general.L2Dissector import L2Dissector
from pcap.dissectors.specific.L2.EthernetDissector import EthernetDissector
from pcap.dissectors.specific.L3.IPv4Dissector import IPv4Dissector
from pcap.dissectors.specific.L4.TCPDissector import TCPDissector
from pcap.dissectors.specific.L4.UDPDissector import UDPDissector


class PacketDissectorException(Exception):
    pass

class PacketDissector:
    __slots__ = ['__l2', '__l3_type', '__l3', '__l4_proto', "__l4", "__dict__"]

    __l2_dissectors = {
        PcapLinkType.LINKTYPE_ETHERNET: EthernetDissector,
    }

    __l3_dissectors = {
        PcapLinkType.LINKTYPE_ETHERNET: {
            "enum": EtherTypes,
            EtherTypes.IPv4: IPv4Dissector,
        }
    }

    __l4_dissectors = {
        IPProto.TCP: TCPDissector,
        IPProto.UDP: UDPDissector,
    }

    @property
    def l2(self):
        return self.__l2

    @property
    def l3(self):
        return self.__l3

    @property
    def l4(self):
        return self.__l4

    def __init__(self, packet: memoryview, linktype: PcapLinkType = PcapLinkType.LINKTYPE_ETHERNET):

        self.__l2 = None
        self.__l3 = None
        self.__l4 = None

        l2_dissector = self.__l2_dissectors.get(linktype)

        if l2_dissector is None:
            raise PacketDissectorException(f"Unsupported/Unknown link type {linktype}")

        self.__l2 = l2_dissector(packet)
        offset = self.__l2.len

        l3_enum = self.__l3_dissectors[linktype]['enum']
        try:
            self.__l3_type = l3_enum(self.__l2.get_upper_layer_type())
        except ValueError:
            raise PacketDissectorException(f"Unsupported/Unknown L3 protocol {self.__l2.get_upper_layer_type()}")

        l3_dissector = self.__l3_dissectors.get(linktype).get(self.__l3_type)

        if l3_dissector is None:
            raise PacketDissectorException(f"Unsupported/Unknown L3 protocol {self.__l3_type}")

        self.__l3 = l3_dissector(packet[offset:])
        offset += self.__l3.len



