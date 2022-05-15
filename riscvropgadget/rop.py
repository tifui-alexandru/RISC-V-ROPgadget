import re
import os
from ctypes import *
from capstone import *

class RISCV_CONSTANTS():
    INSTRUCTION_LEN = 4
    
    JAL_REG_EX  = re.compile(b"[\x6f\xef][\x00-\xff]{3}")
    JALR_REG_EX = re.compile(b"[\x67\xe7][\x00-\xff]{3}") 

    POP_REG_EX = re.compile(b"[\x03\x83][\x00-\x7f][\x01\x11\x21\x31\x41\x51\x61\x71\x81\x91\xa1\xb1\xc1\xd1\xe1\xf1][\x00-\xff]")
    ARITHMETIC_REG_EX = re.compile(b"[\x13\x93][\x00-\xff]{3}")

class GADGET_TYPE():
    POP        = 0b01
    ARITHMETIC = 0b10

class GadgetsCollection():
    def __init__(self, ret_gadget_regex, type_gadget_regex, md):
        self.__ret_gadget_regex = ret_gadget_regex
        self.__type_gadget_regex = type_gadget_regex
        self.__md = md

        # key   -> gadget
        # value -> gadget's vaddr
        self.__gadgets = dict()

    def __is_ret(self, instruction):
        for pattern in self.__ret_gadget_regex:
            if pattern.match(instruction):
                return True
        return False

    def __is_type(self, instruction):
        for pattern in self.__type_gadget_regex:
            if pattern.match(instruction):
                return True
        return False

    def __check_valid_gadget(self, gadget):
        # to be valid a gadget needs to be decoded completely
        # it also needs to be the right type of gadget

        decoded_size = 0
        corret_type = False

        for i in self.__md.disassm(gadget):
            bytecode = gadget[decoded_size : decoded_size + i.size]
            if self.__is_type(bytecode):
                corret_type = True

            decoded_size += i.size

        return (decoded_size == len(gadget) and corret_type == True)

    def find_gadgets(self, exec_sections, gadgets_max_len):
        for section in exec_sections:
            code = section["code"]
            vaddr = section["vaddr"]

            ret_gadgets = []
            for pattern in self.__ret_gadget_regex:
                ret_gadgets += [match.start() for match in re.finditer(pattern, code)]

            for ret_gadget in ret_gadgets:
                ret_start = ret_gadget
                ret_len = next(self.__md.disassm(code[ret_start], 0x1000)).size
                gadget_end = ret_gadget + ret_len

                for i in range(gadgets_max_len):
                    gadget_start = ret_start - i
                    gadget = code[gadget_start : gadget_end]

                    if self.__check_valid_gadget(gadget):
                        new_instruction_len = next(self.__md.disassm(code[gadget_start], 0x1000)).size
                        new_instruction = code[new_instruction : new_instruction + new_instruction_len]

                        if i > 0 and self.__is_ret(new_instruction):
                            break # new gadget begins
                        
                        self.__gadgets[gadget] = vaddr + gadget_start

    def print_gadgets(self, filename, message):
        with open(filename, "w") as fout:
            fout.write(f"{message}\n")
            fout.write(f"A total of {len(self.__gadgets)} gadgets were found \n\n")
            fout.write(f"{'-' * 44}\n")

            cnt_lines = 0

            for gadget in self.__gadgets.keys():
                vaddr = self.__gadgets[gadget]
                gad_str = ""

                for i in self.__md.disasm(gadget, vaddr):
                    gad_str += i.mnemonic + " " + i.op_str + " ; "

                fout.write(f"{hex(vaddr)} : {gad_str}\n")
                
                cnt_lines += 1
                if cnt_lines % 5 == 0:
                    fout.write("\n")

            fout.write("\n-------------- end of gadgets --------------")

class ROP():
    def __init__(self, binary):
        self.__binary  = binary
        self.__gadgets_max_len = 10

        # create output directory if it doesn't exist
        self.__out_dir_path = os.getcwd()
        self.__out_dir_path += "/results"
        if os.path.isdir(self.__out_dir_path) == False:
            os.mkdir(self.__out_dir_path)

        self.__arch_mode = self.__binary.get_arch_mode()
        self.__endianness = self.__binary.get_endianness()

        # key   -> gadget
        # value -> gadget's vaddr
        self.__JOP_pop_gadgets = GadgetsCollection(
            [RISCV_CONSTANTS.JAL_REG_EX, RISCV_CONSTANTS.JALR_REG_EX],
            [RISCV_CONSTANTS.POP_REG_EX],
            Cs(CS_ARCH_RISCV, self.__arch_mode)
        )
        self.__JOP_arithmetic_gadgets = GadgetsCollection(
            [RISCV_CONSTANTS.JAL_REG_EX, RISCV_CONSTANTS.JALR_REG_EX],
            [RISCV_CONSTANTS.ARITHMETIC_REG_EX],
            Cs(CS_ARCH_RISCV, self.__arch_mode)
        )
        self.__JOP_gadgets = GadgetsCollection(
            [RISCV_CONSTANTS.JAL_REG_EX, RISCV_CONSTANTS.JALR_REG_EX],
            [RISCV_CONSTANTS.POP_REG_EX],
            Cs(CS_ARCH_RISCV, self.__arch_mode)
        )

        # duplicate gadgets may occur due to gadget classification

        

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

                    if len(gadget) == RISCV_CONSTANTS.INSTRUCTION_LEN:
                        # the gadget si simply a jump
                        self.__NOP_gadgets[gadget] = vaddr + instruction_start
                        continue

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
                    
    def __print_gadgets(self, filename, gadgets, message):
        with open(self.__out_dir_path + "/" + filename, "w") as fout:

            fout.write(f"{message}\n")
            fout.write(f"A total of {len(gadgets)} gadgets were found \n\n")
            fout.write(f"{'-' * 44}\n")

            cnt_lines = 0

            for gadget in gadgets.keys():
                vaddr = gadgets[gadget]
                gad_str = ""

                for i in self.__md.disasm(gadget, vaddr):
                    gad_str += i.mnemonic + " " + i.op_str + " ; "

                fout.write(f"{hex(vaddr)} : {gad_str}\n")
                
                cnt_lines += 1
                if cnt_lines % 5 == 0:
                    fout.write("\n")

            fout.write("\n-------------- end of gadgets --------------")

    def list_gadgets(self):
        self.__get_JOP_gadgets()

        print(len(self.__JOP_arithmetic_gadgets) + len(self.__JOP_gadgets) + len(self.__JOP_pop_gadgets), "gadgets found\n")
        self.__print_gadgets("pop_jop_gadgets.txt", self.__JOP_pop_gadgets, "POP JOP gadgets")
        self.__print_gadgets("arithmetic_jop_gadgets.txt", self.__JOP_arithmetic_gadgets, "Arithmetic JOP gadgets")
        self.__print_gadgets("jop_gadgets.txt", self.__JOP_gadgets, "JOP gadgets")
        
        self.__print_gadgets("nop_gadgets", self.__NOP_gadgets, "NOP gadgets")

        print(f"Results are available at {self.__out_dir_path}")
