import re
from ctypes import *
from capstone import *

class RISCV_CONSTANTS():
    INSTRUCTION_LEN = 4
    
    JAL_REG_EX  = re.compile(b"[\x6f\xef][\x00-\xff]{3}")
    JALR_REG_EX = re.compile(b"[\x67\xe7][\x00-\xff]{3}") 

    POP_REG_EX = re.compile(b"[\x03\x83][\x00-\x7f]" + 
						  b"[\x01\x03\x05\x07\x09\x0b\x0d\x0f\x11\x13\x15\x17\x19\x1b\x1d\x1f" + \
						  b"\x21\x23\x25\x27\x29\x2b\x2d\x2f\x31\x33\x35\x37\x39\x3b\x3d\x3f" + \
						  b"\x41\x43\x45\x47\x49\x4b\x4d\x4f\x51\x53\x55\x57\x59\\x5b\\x5d\x5f" + \
						  b"\x61\x63\x65\x67\x69\x6b\x6d\x6f\x71\x73\x75\x77\x79\x7b\x7d\x7f" + \
						  b"\x81\x83\x85\x87\x89\x8b\x8d\x8f\x91\x93\x95\x97\x99\x9b\x9d\x9f" + \
						  b"\xa1\xa3\xa5\xa7\xa9\xab\xad\xaf\xb1\xb3\xb5\xb7\xb9\xbb\xbd\xbf" + \
						  b"\xc1\xc3\xc5\xc7\xc9\xcb\xcd\xcf\xd1\xd3\xd5\xd7\xd9\xdb\xdd\xdf" + \
						  b"\xe1\xe3\xe5\xe7\xe9\xeb\xed\xef\xf1\xf3\xf5\xf7\xf9\xfb\xfd\xff]" + \
						  b"[\x00-\xff]")
    ARITHMETIC_REG_EX = re.compile(b"[\x13\x93][\x00-\xff]{3}")

class GADGET_TYPE():
    POP        = 0b01
    ARITHMETIC = 0b10

class ROP():
    def __init__(self, binary):
        self.__binary  = binary
        self.__gadgets_max_len = 10

        # key   -> gadget
        # value -> gadget's vaddr
        self.__JOP_pop_gadgets = dict()
        self.__JOP_arithmetic_gadgets = dict()
        self.__JOP_gadgets = dict()

        # duplicate gadgets may occur due to gadget classification

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
                gadget_type = 0

                for size in range(self.__gadgets_max_len):
                    # get the instruction
                    instruction_start -= RISCV_CONSTANTS.INSTRUCTION_LEN
                    instruction = code[instruction_start : instruction_start + RISCV_CONSTANTS.INSTRUCTION_LEN]

                    if size > 0 and self.__is_gadget_link(instruction, gadget_links):
                        break # another gadget begins

                    # add the instruction to the gadget & determine gadget type
                    gadget = instruction + gadget

                    if self.__has_compressed_instructions(gadget):
                        break # compressed instructions are not supported yet  

                    if RISCV_CONSTANTS.POP_REG_EX.match(instruction):
                        gadget_type |= GADGET_TYPE.POP                          

                    if RISCV_CONSTANTS.ARITHMETIC_REG_EX.match(instruction):
                        gadget_type |= GADGET_TYPE.ARITHMETIC


                    # add the gadget to the collection
                    determined_gadget_type = False

                    if gadget_type & GADGET_TYPE.POP:
                        self.__JOP_pop_gadgets[gadget] = vaddr + instruction_start
                        determined_gadget_type = True
                    if gadget_type & GADGET_TYPE.ARITHMETIC:
                        self.__JOP_arithmetic_gadgets[gadget] = vaddr + instruction_start
                        determined_gadget_type = True
                    
                    if determined_gadget_type == False:
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

        print(len(self.__JOP_arithmetic_gadgets) + len(self.__JOP_gadgets) + len(self.__JOP_pop_gadgets), "gadgets found\n\n")
        self.__print_gadgets(self.__JOP_pop_gadgets, "POP JOP gadgets")
        self.__print_gadgets(self.__JOP_arithmetic_gadgets, "Arithmetic JOP gadgets")
        self.__print_gadgets(self.__JOP_gadgets, "JOP gadgets")