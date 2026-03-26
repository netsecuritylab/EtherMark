from scapy.layers.inet import IP
from config.constants import LABELLED_PCAP_SUFFIX
from ipaddress import IPv4Address, IPv6Address

def mac_starts_with_f2ff(mac: str) -> bool:
    return mac.upper().startswith("F2:FF")

def get_mac_lsb4(mac: str) -> bytes:
    return bytes.fromhex(mac.replace(":", ""))[-4:]

def mac_to_bytes(mac: str) -> bytes:
    return bytes.fromhex(mac.replace(":", ""))

def is_fragment(ip: IP) -> bool:
    return ip.flags.MF or ip.frag != 0

def frag_offset(ip: IP) -> int:
    return ip.frag * 8

def flow_key(ip_src: IPv4Address, sport: int, ip_dst: IPv4Address, dport: int) -> tuple[IPv4Address, int, IPv4Address, int]:
    return (ip_src, sport, ip_dst, dport) if ip_src <= ip_dst else (ip_dst, dport, ip_src, sport)

def labelled_pcap_path(pcap_path: str) -> str:
    return pcap_path + LABELLED_PCAP_SUFFIX
