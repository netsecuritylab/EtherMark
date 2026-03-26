import mmap
import struct
from _socket import IPPROTO_TCP, IPPROTO_UDP
from ipaddress import IPv4Address

from pcap.constants.IEEE802_Numbers import EtherTypes
from pcap.constants.PcapLinkType import PcapLinkType
from pcap.dissectors.specific.L2.EthernetDissector import EthernetDissector
from pcap.dissectors.specific.L3.IPv4Dissector import IPv4Dissector
from pcap.dissectors.specific.L4.TCPDissector import TCPDissector
from pcap.dissectors.specific.L4.UDPDissector import UDPDissector


class MemoryMappedPcapException(Exception):
    pass

class MemoryMappedPcap:
    __GLOBAL_HDR_LEN = 24
    __PACKET_HDR_LEN = 16
    __MAGIC_BE_USEC = 0xA1B2C3D4
    __MAGIC_BE_NSEC = 0xA1B23C4D
    __MAGIC_LE_USEC = 0xD4C3B2A1
    __MAGIC_LE_NSEC = 0x4D3CB2A1

    def __init__(self, path, write=False, unpack=True):
        self.__path: str = path
        self.__unpack: bool = unpack
        self.__file = open(self.__path, 'r+b' if write else 'rb')
        self.__mm = mmap.mmap(
            self.__file.fileno(),
            0,
            access=mmap.ACCESS_WRITE if write else mmap.ACCESS_READ
        )
        self.__mv: memoryview = memoryview(self.__mm)

        # Check endianess
        global_hdr = self.__mv[:self.__GLOBAL_HDR_LEN]
        self.__ghdr = global_hdr
        self.__endian = ">"

        magic = struct.unpack(f"{self.__endian}I", global_hdr[:4])[0]
        if magic == self.__MAGIC_BE_USEC:
            s = "usec timestamp (big-endian)"
            self.__ts_resolution = 'u'
        elif magic == self.__MAGIC_BE_NSEC:
            s ="nsec timestamp (big-endian)"
            self.__ts_resolution = 'n'
        elif magic == self.__MAGIC_LE_USEC:
            s = "usec timestamp (little-endian)"
            self.__endian = "<"
            self.__ts_resolution = 'u'
        elif magic == self.__MAGIC_LE_NSEC:
            s = "nsec timestamp (little-endian)"
            self.__endian = "<"
            self.__ts_resolution = 'n'
        else:
            raise MemoryMappedPcapException("Unsupported or invalid PCAP magic number")

        ver_major, ver_minor, res1, res2, snaplen, linktype = struct.unpack(
            self.__endian + 'HHiiii', global_hdr[4:]
        )

        self.__major = ver_major
        self.__minor = ver_minor
        self.__snaplen = snaplen

        try:
            self.__linktype = PcapLinkType(linktype & 0xFFFF)
        except ValueError:
            raise MemoryMappedPcapException("Invalid linktype")

        self.__gInfo = f"PCAP {self.__major}.{self.__minor} {s}\n{self.__linktype}"

        self.__offset = self.__GLOBAL_HDR_LEN


    @property
    def g_hdr(self):
        return self.__ghdr

    @property
    def global_info(self):
        return self.__gInfo

    @property
    def link_type(self):
        return self.__linktype

    @property
    def endianness(self):
        return self.__endian

    @property
    def ts_resolution(self):
        return self.__ts_resolution

    def __iter__(self):
        return self

    def __next__(self):
        if self.__offset + self.__PACKET_HDR_LEN > len(self.__mm):
            raise StopIteration
        pkt_hdr = self.__mv[self.__offset:self.__offset + self.__PACKET_HDR_LEN]
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(self.__endian + 'IIII', pkt_hdr)
        self.__offset += self.__PACKET_HDR_LEN
        if self.__offset + incl_len > len(self.__mm):
            raise StopIteration
        packet_view = self.__mv[self.__offset:self.__offset + incl_len]
        self.__offset += incl_len
        if self.__unpack:
            return (ts_sec, ts_usec, incl_len, orig_len), packet_view
        else:
            return pkt_hdr, packet_view

    def close(self):
        self.__file.close()

