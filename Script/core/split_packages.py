import os
import struct

from config.constants import LABEL_BYTES_PREFIX
from pcap.MemoryMappedPcap import MemoryMappedPcap
from pcap.dissectors.specific.L2.EthernetDissector import EthernetDissector


def split_pcap(pcap_path, pkgs):
    total_packets = 0
    files = dict()
    pcap = MemoryMappedPcap(pcap_path, unpack=False)

    base_dir = os.path.dirname(os.path.abspath(pcap_path))
    pkg_dir = os.path.join(base_dir, "packages")

    os.makedirs(pkg_dir, exist_ok=True)

    for raw_hdr, packet in pcap:
        total_packets += 1
        eth = EthernetDissector(packet)

        if eth.dst_mac[:2] == LABEL_BYTES_PREFIX and eth.src_mac[:2] == LABEL_BYTES_PREFIX:
            raise Exception("Two EtherMark labels found, weird!")
        elif eth.dst_mac[:2] == LABEL_BYTES_PREFIX:
            ethermark_label = struct.unpack("!I", eth.dst_mac[2:])[0]
        elif eth.src_mac[:2] == LABEL_BYTES_PREFIX:
            ethermark_label = struct.unpack("!I", eth.src_mac[2:])[0]
        else:
            continue

        f = files.get(ethermark_label)

        if f is None:
            pkg_name = pkgs.get(ethermark_label, str(ethermark_label))
            this_pkg_dir = os.path.join(pkg_dir, pkg_name)
            os.makedirs(this_pkg_dir, exist_ok=True)
            f = open(os.path.join(this_pkg_dir, f"{pkg_name}.pcap"), "wb")
            files[ethermark_label] = f
            f.write(pcap.g_hdr)

        f.write(raw_hdr)
        f.write(packet)

    pcap.close()

    for f in files.values():
        f.close()