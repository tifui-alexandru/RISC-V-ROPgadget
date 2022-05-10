import re
from ctypes import *
from capstone import *

from riscvropgadget.structures.trie import Trie

class RISCV_CONSTANTS():
    INSTRUCTION_LEN = 4
    JAL_OPCODE = b"[\x6f\x8f]"
    JALR_OPCODE = b"[\x67\x87]"

class ROP():
    def __init__(self, binary):
        self.__binary  = binary
        self.__gadgets = Trie()
        self.__gadgets_max_len = 10

    def __is_gadget_link(self, instruction, gadget_links):
        for pattern in gadget_links:
            if pattern.match(instruction):
                return True
        return False
        
    def __get_JOP_gadgets(self):
        arch_mode = self.__binary.get_arch_mode()
        endianness = self.__binary.get_endianness()
        
        md = Cs(CS_MODE_RISCV64, arch_mode + endianness)
        
        if endianness == CS_MODE_LITTLE_ENDIAN:
            gadget_links = [re.compile(b"[\x00-\xff]{3}" + RISCV_CONSTANTS.JAL_OPCODE),
                            re.compile(b"[\x00-\xff]{3}" + RISCV_CONSTANTS.JALR_OPCODE)]
        else:
            gadget_links = [re.compile(RISCV_CONSTANTS.JAL_OPCODE  + b"[\x00-\xff]{3})"),
                            re.compile(RISCV_CONSTANTS.JALR_OPCODE + b"[\x00-\xff]{3})")]

        exec_sections = self.__binary.get_exec_sections()

        for section in exec_sections:
            chain_start = None
            chain_end = None

            for instruction_end in range(len(section), 0, -RISCV_CONSTANTS.INSTRUCTION_LEN):
                instruction = section["code"][instruction_end - RISCV_CONSTANTS.INSTRUCTION_LEN : instruction_end]

                if self.__is_gadget_link(instruction, gadget_links):
                    chain_end = instruction_end
                    chain_start = instruction_end
                
                if chain_start is not None and chain_end - chain_start < self.__gadgets_max_len:
                    chain_start = instruction_end - RISCV_CONSTANTS.INSTRUCTION_LEN

                    rop_chain = ""
                    rop_addr = None

                    for i in md.disasm(section["code"][chain_start : chain_end], section["vaddr"] + chain_start):
                        if rop_addr is None:
                            rop_addr = str(hex(i.address))
                            rop_chain += f"{rop_addr}: "

                            rop_chain += i.mnemonic + " " + i.op_str + " ; "
                    
                    rop_chain = rop_chain[:-3]

                    self.__gadgets.insert(rop_chain)

    def list_gadgets(self):
        self.__get_JOP_gadgets()

        if self.__gadgets.is_empty():
            print("No gadgets were found")
        else:
            self.__gadgets.list_all()
            print("\n----------- end of gadgets --------------")