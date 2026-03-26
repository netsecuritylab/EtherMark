import argparse

from cli.commons import print_separator_line, print_with_prefix, spinning
from core.split_packages import split_pcap


def add_split_subparser(subparsers):
    rel_parser = subparsers.add_parser(
        "split",
        help="Split a PCAP file in one PCAP file per Android package.",
    )
    rel_parser.add_argument(
        "-p", "--packages-list",
        help="File containing a mapping from UID to package name.",
    )
    rel_parser.add_argument(
        "pcap_path",
        help="A path to the PCAP file to be split."
    )

    rel_parser.set_defaults(func=handle_split)


def handle_split(args):
    pkgs = dict()
    dup_uids = set()
    try:
        with open(args.packages_list, "r") as pkg_file:
            for line in pkg_file:
                parts = line.split()
                package = parts[0].split(":")[1]
                uid = int(parts[1].split(":")[1])
                if pkgs.get(uid) is not None:
                    dup_uids.add(uid)
                pkgs[uid] = package

    except Exception as e:
        pass

    for dup in dup_uids:
        if dup in pkgs:
            del pkgs[dup]

    print_separator_line(40)
    print_with_prefix(f"Reading PCAP file from......: {args.pcap_path}")
    print_with_prefix(f"Reading packages map from...: {args.packages_list}")
    print_separator_line(40)

    with spinning("Splitting PCAP", 29):
        split_pcap(args.pcap_path, pkgs)
