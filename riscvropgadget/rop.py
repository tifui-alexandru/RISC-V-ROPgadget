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

        self.__arch_mode = self.__binary.get_arch_mode()
        self.__endianness = self.__binary.get_endianness()
        
        self.__md = Cs(CS_MODE_RISCV64, self.__arch_mode + self.__endianness)

    def __is_gadget_link(self, instruction, gadget_links):
        for pattern in gadget_links:
            if pattern.match(instruction):
                return True
        return False
        
    def __get_JOP_gadgets(self):
        if self.__endianness == CS_MODE_LITTLE_ENDIAN:
            gadget_links = [re.compile(b"[\x00-\xff]{3}" + RISCV_CONSTANTS.JAL_OPCODE),
                            re.compile(b"[\x00-\xff]{3}" + RISCV_CONSTANTS.JALR_OPCODE)]
        else:
            gadget_links = [re.compile(RISCV_CONSTANTS.JAL_OPCODE  + b"[\x00-\xff]{3})"),
                            re.compile(RISCV_CONSTANTS.JALR_OPCODE + b"[\x00-\xff]{3})")]

        exec_sections = self.__binary.get_exec_sections()

        for section in exec_sections:
            current_chain = []
            found_gadgets = False

            code = section["code"]
            vaddr = section["vaddr"]

            for instruction_end in range(len(code), 0, -RISCV_CONSTANTS.INSTRUCTION_LEN):
                instruction = code[instruction_end - RISCV_CONSTANTS.INSTRUCTION_LEN : instruction_end]

                if self.__is_gadget_link(instruction, gadget_links):
                    current_chain = []
                    found_gadgets = True
                
                if len(current_chain) < self.__gadgets_max_len and found_gadgets:
                    chain_start = instruction_end - RISCV_CONSTANTS.INSTRUCTION_LEN
                    current_chain.append(instruction)
                    self.__gadgets.insert(current_chain, vaddr + chain_start)
                    

    def list_gadgets(self):
        self.__get_JOP_gadgets()

        if self.__gadgets.is_empty():
            print("No gadgets were found")
        else:
            for rop_chain in self.__gadgets.list_all():
                code = b"".join(rop_chain["code"][::-1])
                vaddr = rop_chain["vaddr"]

                rop_addr = None
                rop_decoded = ""

                for i in self.__md.disasm(code, vaddr):
                    if rop_addr is None:
                        rop_addr = str(hex(i.address))
                        rop_decoded += f"{rop_addr}: "
                    
                    rop_decoded += i.mnemonic + " " + i.op_str + " ; "

                print(rop_decoded)

            print("\n----------- end of gadgets --------------")