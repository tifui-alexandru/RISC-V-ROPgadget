import argparse 
from loaders.elf import *
from rop.rop import *

if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument(dest="binary", help="path to binary")

    args = parser.parse_args()

    binary = ELF(args["binary"])
    rop = ROP(binary)

    rop.list_gadgets()