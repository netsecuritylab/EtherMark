import struct
import sys
from _socket import IPPROTO_UDP, IPPROTO_TCP
from ipaddress import IPv4Address

from config.constants import LABEL_BYTES_PREFIX
from pcap.MemoryMappedPcap import MemoryMappedPcap
from pcap.constants.IEEE802_Numbers import EtherTypes
from pcap.dissectors.specific.L2.EthernetDissector import EthernetDissector
from pcap.dissectors.specific.L3.IPv4Dissector import IPv4Dissector
from pcap.dissectors.specific.L4.TCPDissector import TCPDissector
from pcap.dissectors.specific.L4.UDPDissector import UDPDissector
from pcap.constants.PcapLinkType import PcapLinkType

# Label map: (proto, src_ip, src_port, dst_ip, dst_port) -> dst_mac
mac_map = {}

total_packets = 0

def compute_udp(pkt, eth, src_ip, dst_ip):
    udp = UDPDissector(pkt)
    sport = udp.get_sport()
    dport = udp.get_dport()

    if eth.dst_mac[:2] == LABEL_BYTES_PREFIX:
        mac_map[('U', src_ip, sport, dst_ip, dport)] = bytes(eth.dst_mac)
    else:
        key = ('U', dst_ip, dport, src_ip, sport)
        label = mac_map.get(key)
        if label is not None:
            eth.src_mac = label
        else:
            print(f"[ERROR] No mapping for reply from ({src_ip}:{sport}) "
                  f"to ({dst_ip}:{dport}) at packet {total_packets}", file=sys.stderr)

def compute_tcp(pkt, eth, src_ip, dst_ip):
    tcp = TCPDissector(pkt)
    flags = struct.unpack("!B", tcp.flags)[0]
    is_rst = bool(flags & 0x04)
    is_ack = bool(flags & 0x10)
    sport =  tcp.get_sport()
    dport = tcp.get_dport()

    if eth.dst_mac[:2] == LABEL_BYTES_PREFIX:
        if (is_ack or is_rst) and not (is_rst and is_ack):
            saved_mac = mac_map.get(('T', src_ip, sport, dst_ip, dport))
            if saved_mac is not None:
                if eth.dst_mac == bytes([0xF2, 0xFF, 0x00, 0x00, 0x00, 0x00]):
                    eth.dst_mac = saved_mac
                    return
            else:
                return

        mac_map[('T', src_ip, sport, dst_ip, dport)] = bytes(eth.dst_mac)

    else:
        key = ('T', dst_ip, dport, src_ip, sport)
        label = mac_map.get(key)
        if label is not None:
            eth.src_mac = label
        else:
            print(f"[ERROR] No mapping for reply from ({src_ip}:{sport}) "
                  f"to ({dst_ip}:{dport}) at packet {total_packets}", file=sys.stderr)

def compute(pcap_path, devices):
    global total_packets
    pcap = MemoryMappedPcap(pcap_path, write=True)

    if pcap.link_type != PcapLinkType.LINKTYPE_ETHERNET:
        raise Exception(f"Expected an Ethernet pcap (LINKTYPE_ETHERNET) instead got: {pcap.link_type.name}")

    dev_set = {IPv4Address(x) for x in devices}

    for hdr, packet in pcap:
        total_packets += 1
        eth = EthernetDissector(packet)
        ether_type = eth.get_upper_layer_type()
        offset = eth.len

        if ether_type == EtherTypes.IPv4.value:
            ipv4 = IPv4Dissector(packet[offset:])
            offset += ipv4.len
            proto = ipv4.get_upper_layer_protocol()

            src_ip = IPv4Address(ipv4.get_src_ip())
            dst_ip = IPv4Address(ipv4.get_dst_ip())

            # This packet does not belong to any specified device
            if src_ip not in dev_set and dst_ip not in dev_set:
                continue

            if proto == IPPROTO_UDP:
                compute_udp(packet[offset:], eth, src_ip, dst_ip)

            elif proto == IPPROTO_TCP:
                compute_tcp(packet[offset:], eth, src_ip, dst_ip)


    pcap.close()