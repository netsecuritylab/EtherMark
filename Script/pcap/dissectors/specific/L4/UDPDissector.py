import struct

from pcap.constants.constants import UDP_HEADER_LENGTH

class UDPDissectorException(Exception):
    pass

class UDPDissector:
    __slots__ = ('__sport', '__dport', '__payload', '__hdr')

    def __init__(self, mv: memoryview):
        if len(mv) < UDP_HEADER_LENGTH:
            raise UDPDissectorException('Packet is smaller than UDP header length')

        self.__hdr = mv[:UDP_HEADER_LENGTH]
        self.__payload = mv[UDP_HEADER_LENGTH:]
        self.__sport = mv[:2]
        self.__dport = mv[2:4]

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
    def payload(self):
        return self.__payload

    @property
    def hdr(self):
        return self.__hdr

    @property
    def len(self):
        return len(self.__hdr)

