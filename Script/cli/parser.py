import argparse

from cli.commands.label_expansion import add_le_subparser
from cli.commands.split_packages import add_split_subparser


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="EtherMark Swiss-Knife tool")
    subparsers = parser.add_subparsers(dest="command", required=True, help="Available commands")
    
    add_le_subparser(subparsers)
    add_split_subparser(subparsers)
    
    return parser
