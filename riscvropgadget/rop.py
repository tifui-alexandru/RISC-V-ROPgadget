import re
from ctypes import *
from capstone import *

class RISCV_CONSTANTS():
    INSTRUCTION_LEN = 4
    
    JAL_REG_EX  = re.compile(b"[\x6f\xef][\x00-\xff]{3}")
    JALR_REG_EX = re.compile(b"[\x67\xe7][\x00-\xff]{3}") 

    ARITHMETIC_REG_EX = re.compile(b"[\x13\x93][\x00-\xff]{3}")

class GADGET_TYPE():
    ARITHMETIC = 1
    OTHER = 2

class ROP():
    def __init__(self, binary):
        self.__binary  = binary
        self.__gadgets_max_len = 10

        # key   -> gadget
        # value -> gadget's vaddr
        self.__JOP_arithmetic_gadgets = dict()
        self.__JOP_gadgets = dict()

        self.__arch_mode = self.__binary.get_arch_mode()
        self.__endianness = self.__binary.get_endianness()
        
        self.__md = Cs(CS_ARCH_RISCV, self.__arch_mode)

    def __is_gadget_link(self, instruction, gadget_links):
        for pattern in gadget_links:
            if pattern.match(instruction):
                return True
        return False

    def __has_compressed_instructions(self, gadget):
        cnt = 0
        for _ in self.__md.disasm(gadget, 0x1000):
            cnt += 1

        return (cnt * RISCV_CONSTANTS.INSTRUCTION_LEN != len(gadget))
        
    def __get_JOP_gadgets(self):
        gadget_links = [RISCV_CONSTANTS.JAL_REG_EX, RISCV_CONSTANTS.JALR_REG_EX]

        exec_sections = self.__binary.get_exec_sections()

        if self.__endianness == CS_MODE_BIG_ENDIAN:
            exec_sections = [section[::-1] for section in exec_sections] # convert to little endian

        for section in exec_sections:
            code = section["code"]
            vaddr = section["vaddr"]

            ret_gadgets = []
            for pattern in gadget_links:
                ret_gadgets += [match.start() for match in re.finditer(pattern, code)]

            for ret_gadget in ret_gadgets:
                instruction_start = ret_gadget + RISCV_CONSTANTS.INSTRUCTION_LEN

                gadget = b""
                gadget_type = GADGET_TYPE.OTHER

                for size in range(self.__gadgets_max_len):
                    instruction_start -= RISCV_CONSTANTS.INSTRUCTION_LEN
                    instruction = code[instruction_start : instruction_start + RISCV_CONSTANTS.INSTRUCTION_LEN]

                    if size > 0 and self.__is_gadget_link(instruction, gadget_links):
                        break # another gadget begins

                    gadget = instruction + gadget

                    if self.__has_compressed_instructions(gadget):
                        break # compressed instructions are not supported yet                             

                    if RISCV_CONSTANTS.ARITHMETIC_REG_EX.match(instruction):
                        gadget_type = GADGET_TYPE.ARITHMETIC

                    if gadget_type == GADGET_TYPE.ARITHMETIC:
                        self.__JOP_arithmetic_gadgets[gadget] = vaddr + instruction_start
                    else:
                        self.__JOP_gadgets[gadget] = vaddr + instruction_start
                    
    def __print_gadgets(self, gadgets, message):
        print(message)
        print("A total of", len(gadgets), "were found \n\n")
        print("-" * 44, "\n")

        cnt_lines = 0

        for gadget in gadgets.keys():
            vaddr = gadgets[gadget]
            gad_str = ""

            for i in self.__md.disasm(gadget, vaddr):
                gad_str += i.mnemonic + " " + i.op_str + " ; "

            print(hex(vaddr), ":", gad_str)
            
            cnt_lines += 1
            if cnt_lines % 5 == 0:
                print("\n")

        print("\n-------------- end of gadgets --------------")

    def list_gadgets(self):
        self.__get_JOP_gadgets()

        print(len(self.__JOP_arithmetic_gadgets) + len(self.__JOP_gadgets), "gadgets found\n\n")
        self.__print_gadgets(self.__JOP_arithmetic_gadgets, "Arithmetic JOP gadgets")
        self.__print_gadgets(self.__JOP_gadgets, "JOP gadgets")