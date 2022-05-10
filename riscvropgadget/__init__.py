import argparse 

import riscvropgadget.loaders
import riscvropgadget.structures

def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(dest="binary", help="path to binary")

    args = parser.parse_args()

    from riscvropgadget.loaders.elf import ELF
    from riscvropgadget.rop import ROP

    binary = ELF(args.binary)
    rop = ROP(binary)

    rop.list_gadgets()