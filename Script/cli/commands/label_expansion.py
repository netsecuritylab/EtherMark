import os

from cli.commons import print_separator_line, print_with_prefix, spinning
from core.commons import labelled_pcap_path
from core.label_expansion import process_pcap
from core.label_expansion_inplace import compute


def add_le_subparser(subparsers):
    le_parser = subparsers.add_parser(
        "lexpand",
        help="Perform EtherMark label expansion on a EtherMark outbound-labelled PCAP."
    )
    le_parser.add_argument(
        "--in-place",
        required=False,
        action="store_true",
        help="Perform label expansion in-place"
    )
    le_parser.add_argument(
        "DIR",
        type=str,
        help="Path to the DIR containing pcap file to be label expanded 'packets.pcap' and the list of devices 'devices.txt'"
    )
    le_parser.set_defaults(func=handle_le)

def handle_le(args):
    pcap_path = os.path.join(args.DIR, "packets.pcap")
    devices_path = os.path.join(args.DIR, "devices.txt")
    output_path = labelled_pcap_path(pcap_path)

    print_separator_line(40)
    print_with_prefix(f"Reading pcap from...........: {pcap_path}")
    print_with_prefix(f"Reading devices list from...: {devices_path}")

    with open(devices_path, "r") as f:
        devices = {line.strip().split(" ")[0] for line in f if line.strip()}


    if args.in_place:
        with spinning("Expanding labels in-place", 29):
            compute(pcap_path, devices)

    else:
        with spinning("Expanding labels", 29):
            process_pcap(pcap_path, output_path, devices)