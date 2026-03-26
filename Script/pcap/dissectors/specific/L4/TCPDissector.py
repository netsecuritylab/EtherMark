from pcap.constants.constants import TCP_HEADER_LENGTH
import struct

class TCPDissectorException(Exception):
    pass

class TCPDissector:
    __slots__ = ('__sport', '__dport', '__flags', '__payload', '__hdr')

    def __init__(self, mv: memoryview):
        if len(mv) < TCP_HEADER_LENGTH:
            raise TCPDissectorException('Packet is smaller than minimum TCP header length')

        hdr_len = ((struct.unpack("!B", mv[12:13])[0] & 0xF0) >> 4) * 4

        if len(mv) < hdr_len:
            raise TCPDissectorException('Packet is smaller than TCP header length')

        self.__hdr = mv[:hdr_len]
        self.__payload = mv[hdr_len:]
        self.__sport = mv[:2]
        self.__dport = mv[2:4]
        self.__flags = mv[13:14]

    @property
    def sport(self):
        return self.__sport

    @property
    def dport(self):
        return self.__dport

    def get_sport(self):
        return struct.unpack("!H", self.__sport)[0]

    def get_dport(self):
        return struct.unpack("!H", self.__dport)[0]

    @property
    def flags(self):
        return self.__flags

    @property
    def payload(self):
        return self.__payload

    @property
    def hdr(self):
        return self.__hdr

    @property
    def len(self):
        return len(self.__hdr)

