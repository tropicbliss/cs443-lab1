from remove_warnings import remove_warnings

remove_warnings()

import argparse
import os

parser = argparse.ArgumentParser(description="Binary Analysis Tool - Analyse binary files for security and understanding")
subparsers = parser.add_subparsers(title="subcommands", description="valid subcommands", help="additional help", dest="command", required=True)
a_parser = subparsers.add_parser("cfg", help="Control-flow graph generation")
a_parser.add_argument("binary", help="Path to the binary file to analyse")

b_parser = subparsers.add_parser("symexec", help="Symbolic execution")
b_parser.add_argument("binary", help="Path to the binary file to analyse")

args = parser.parse_args()

binary_path = args.binary
if args.command == "cfg":
    import cfg_gen
    cfg_gen.gen(binary_path)
else:
    import sym_exec
    sym_exec.exec(binary_path)