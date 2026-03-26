from scapy.all import (
    PcapReader, PcapWriter
)
from scapy.layers.inet import IP, Ether, TCP, UDP
import argparse
import sys
import time

from core.commons import is_fragment, frag_offset, mac_starts_with_f2ff

# Label map: (proto, src_ip, src_port, dst_ip, dst_port) -> dst_mac
mac_map = {}
# For reply fragmentation support: (src_ip, dst_ip, ip_id) -> dst_port
frag_lookup = {}

def process_packet(pkt, pkt_index, devices):
    if not (IP in pkt and Ether in pkt):
        return None  # not IPv4 or no Ethernet layer
    
    ether = pkt[Ether]
    ip    = pkt[IP]
    
    # Check if Source IP or Destination IP
    # is from expected devices, if not skip packet.
    if (ip.src not in devices) and (ip.dst not in devices):
        return None
    
    
    l4 = pkt[TCP] if TCP in pkt else pkt[UDP] if UDP in pkt else None

    frag = is_fragment(ip)
    offset = frag_offset(ip)

    if mac_starts_with_f2ff(ether.dst):
        # Outbound packet that was labelled
        if frag and offset != 0:
            # Skip mapping for non-first fragment
            return pkt
        if l4:
            l4_id = 'T' if TCP in pkt else 'U'

            if TCP in pkt:
                if l4.flags == 'R' or l4.flags == 'A':
                    saved_mac =  mac_map.get((l4_id, ip.src, l4.sport, ip.dst, l4.dport))
                    if saved_mac is not None:
                        if "F2:FF:00:00:00:00" == ether.dst.upper():
                            ether.dst = saved_mac
                            return pkt
                    else:
                        return pkt
                        #raise Exception("RST packet not belonging to any seen flow.")


            mac_map[(l4_id, ip.src, l4.sport, ip.dst, l4.dport)] = ether.dst
    else:
        # Inbound packet (to be labelled)
        if frag:
            if offset == 0:
                # First fragment: must have L4 header
                if not l4:
                    print(f"[ERROR] [Inbound] First fragment without L4 header at packet {pkt_index}", file=sys.stderr)
                    return pkt
                l4_id = 'T' if TCP else 'U'
                frag_lookup[(ip.src, ip.dst, ip.id)] = (l4_id, l4.sport, l4.dport)
            else:
                # Subsequent fragment: find stored info
                key = (ip.src, ip.dst, ip.id)
                if key not in frag_lookup:
                    print(f"[PANIC] Out-of-order or missing first fragment for IPID={ip.id} at packet {pkt_index}", file=sys.stderr)
                    return pkt
                # Retrieve info for MAC map lookup
                sav_l4, saved_sport, saved_dport = frag_lookup[key]
                key_mac = (sav_l4, ip.dst, saved_dport, ip.src, saved_sport)
                if key_mac in mac_map:
                    ether.src = mac_map[key_mac]
                else:
                    print(f"[ERROR] No MAC mapping for reply fragment #{pkt_index} (key={key_mac})", file=sys.stderr)
                return pkt  # done for fragment
        
        # Not-fragmented packet
        if l4:
            l4_id = 'T' if TCP in pkt else 'U'
            key = (l4_id, ip.dst, l4.dport, ip.src, l4.sport)
            if key in mac_map:
                ether.src = mac_map[key]
            else:
                print(f"[ERROR] No mapping for reply from ({ip.src}:{l4.sport}) "
                      f"to ({ip.dst}:{l4.dport}) at packet {pkt_index}", file=sys.stderr)

    return pkt

def process_pcap(in_pcap: str, out_pcap: str, devices):
    count = 0
    with PcapReader(in_pcap) as reader, PcapWriter(out_pcap, append=False, sync=True) as writer:
        for pkt in reader:
            count += 1
            try:
                pkt = process_packet(pkt, count, devices)
                
                if pkt is None:
                    continue
                
            except Exception as e:
                print(f"[WARN] Packet #{count} processing error: {e}", file=sys.stderr)
            writer.write(pkt)
    print(f"Processed {count} packets. Mappings stored: {len(mac_map)}, Frag lookups: {len(frag_lookup)}")



