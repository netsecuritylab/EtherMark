#!/usr/bin/env python3

from cli.parser import build_parser

def main():
   parser = build_parser()
   args = parser.parse_args()
   args.func(args)

if __name__ == "__main__":
    main()