from typing import override

from pcap.constants.constants import IPV4_HEADER_LENGTH
import struct

from pcap.dissectors.general.L3Dissector import L3Dissector


class IPv4DissectorException(Exception):
    pass

class IPv4Dissector(L3Dissector):
    __slots__ = ('__src_ip', '__dst_ip', '__protocol', '__hdr')

    def __init__(self, mv: memoryview):
        if len(mv) < IPV4_HEADER_LENGTH:
            raise IPv4DissectorException('Packet is smaller than minimum IPv4 header length')

        ihl = (struct.unpack("!B", mv[:1])[0] & 0x0F) * 4

        if len(mv) < ihl:
            raise IPv4DissectorException('Packet is smaller than IPv4 header length')

        self.__protocol = mv[9:10]
        self.__src_ip = mv[12:16]
        self.__dst_ip = mv[16:20]
        self.__hdr = mv[:ihl]


    @property
    def src_ip(self):
        return self.__src_ip

    @property
    def dst_ip(self):
        return self.__dst_ip

    @property
    def protocol(self):
        return self.__protocol

    def get_src_ip(self):
        return struct.unpack("!I", self.__src_ip)[0]

    def get_dst_ip(self):
        return struct.unpack("!I", self.__dst_ip)[0]

    @override
    def get_upper_layer_protocol(self) -> int:
        return struct.unpack("!B", self.__protocol)[0]

    @property
    def hdr(self):
        return self.__hdr

    @property
    def len(self):
        return len(self.__hdr)

