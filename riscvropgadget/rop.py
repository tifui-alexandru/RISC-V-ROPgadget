import re
from ctypes import *
from capstone import *

from riscvropgadget.structures.trie import Trie

class RISCV_CONSTANTS():
    INSTRUCTION_LEN    = 4
    
    JAL_REG_EX  = re.compile(b"[\x6f\xef][\x00-\xff]{3}")
    JALR_REG_EX = re.compile(b"[\x67\xe7][\x00-\xff]{3}") 

    ARITHMETIC_REG_EX = re.compile(b"[\x13\x93][\x00-\xff]{3}")

class CHAIN_TYPE():
    ARITHMETIC = 1
    OTHER = 2

class ROP():
    def __init__(self, binary):
        self.__binary  = binary
        self.__gadgets_max_len = 20

        self.__JOP_arithmetic_gadgets = Trie()
        self.__JOP_gadgets = Trie()

        self.__arch_mode = self.__binary.get_arch_mode()
        self.__endianness = self.__binary.get_endianness()
        
        self.__md = Cs(CS_ARCH_RISCV, self.__arch_mode)

    def __is_gadget_link(self, instruction, gadget_links):
        for pattern in gadget_links:
            if pattern.match(instruction):
                return True
        return False
        
    def __get_JOP_gadgets(self):
        gadget_links = [RISCV_CONSTANTS.JAL_REG_EX, RISCV_CONSTANTS.JALR_REG_EX]

        exec_sections = self.__binary.get_exec_sections()

        if self.__endianness == CS_MODE_BIG_ENDIAN:
            exec_sections = [section[::-1] for section in exec_sections] # convert to little endian

        for section in exec_sections:
            current_chain = []
            found_gadgets = False
            chain_type = CHAIN_TYPE.OTHER

            code = section["code"]
            vaddr = section["vaddr"]

            for instruction_end in range(len(code), 0, -RISCV_CONSTANTS.INSTRUCTION_LEN):
                instruction_start = instruction_end - RISCV_CONSTANTS.INSTRUCTION_LEN
                instruction = code[instruction_start : instruction_end]

                if self.__is_gadget_link(instruction, gadget_links):
                    current_chain = []
                    found_gadgets = True
                    chain_type = CHAIN_TYPE.OTHER
                
                if len(current_chain) < self.__gadgets_max_len and found_gadgets:
                    current_chain.append(instruction)

                    if RISCV_CONSTANTS.ARITHMETIC_REG_EX.match(instruction):
                        chain_type = CHAIN_TYPE.ARITHMETIC

                    if chain_type == CHAIN_TYPE.ARITHMETIC:
                        self.__JOP_arithmetic_gadgets.insert(current_chain, vaddr + instruction_start)
                    else:
                        self.__JOP_gadgets.insert(current_chain, vaddr + instruction_start)

    def __print_gadgets(self, gadgets, message):
        print(message)
        print("-" * 44, "\n")

        total_gadgets = 0

        if gadgets.is_empty():
            print("No gadgets were found")
        else:
            for rop_chain in gadgets.list_all():
                code = b"".join(rop_chain["code"][::-1])
                vaddr = rop_chain["vaddr"]

                rop_addr = None
                rop_decoded = ""

                debug_counter = 0
                for i in self.__md.disasm(code, vaddr):
                    debug_counter += 1

                    if rop_addr is None:
                        rop_addr = str(hex(i.address))
                        rop_decoded += f"{rop_addr}: "
                    
                    rop_decoded += i.mnemonic + " " + i.op_str + " ; "

                if len(rop_decoded) > 0:
                    total_gadgets += 1
                    print(rop_decoded)

        print("\n-------------- end of gadgets --------------")
        print("A total of", total_gadgets, "were found \n\n")

    def list_gadgets(self):
        self.__get_JOP_gadgets()
        self.__print_gadgets(self.__JOP_arithmetic_gadgets, "Arithmetic JOP gadgets")
        self.__print_gadgets(self.__JOP_gadgets, "JOP gadgets")