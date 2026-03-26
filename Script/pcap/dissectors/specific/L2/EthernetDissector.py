import struct
from typing import override

from pcap.constants.constants import ETHERNET_HEADER_LENGTH
from pcap.dissectors.general.L2Dissector import L2Dissector


class EthernetDissectorException(Exception):
    pass

class EthernetDissector(L2Dissector):
    __slots__ = ('__src_mac', '__dst_mac', '__ether_type', '__hdr')

    def __init__(self, mv: memoryview):

        super().__init__()

        if len(mv) < ETHERNET_HEADER_LENGTH:
            raise EthernetDissectorException('Packet is smaller than Ethernet header length')

        self.__hdr = mv[:ETHERNET_HEADER_LENGTH]
        self.__dst_mac = mv[:6]
        self.__src_mac = mv[6:12]
        self.__ether_type = mv[12:ETHERNET_HEADER_LENGTH]


    @property
    def dst_mac(self):
        return self.__dst_mac

    @dst_mac.setter
    def dst_mac(self, value):
        if len(value) != 6:
            raise ValueError("MAC address must be 6 bytes")
        self.__dst_mac[:] = value

    @property
    def src_mac(self):
        return self.__src_mac

    @src_mac.setter
    def src_mac(self, value):
        if len(value) != 6:
            raise ValueError("MAC address must be 6 bytes")

        self.__src_mac[:] = value

    @property
    def ether_type(self):
        return self.__ether_type

    @override
    def get_upper_layer_type(self):
        return struct.unpack('!H', self.__ether_type)[0]

    @property
    def hdr(self):
        return self.__hdr

    @property
    def len(self):
        return len(self.__hdr)

