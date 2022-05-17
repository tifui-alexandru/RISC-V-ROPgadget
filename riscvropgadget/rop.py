import re
import os
from ctypes import *
from capstone import *

class RISCV_CONSTANTS():
    INSTRUCTION_LEN = 4
    
    JAL_REG_EX  = re.compile(b"[\x6f\xef][\x00-\xff]{3}")
    JALR_REG_EX = re.compile(b"[\x67\xe7][\x00-\xff]{3}") 
    ECALL_REG_EX = re.compile(b"\x73\x00\x00\x00")

    JAL_C_REG_EX = re.compile(b"[\x01\x05\x09\x0d\x11\x15\x19\x1d" +
                              b"\x21\x25\x29\x2d\x31\x35\x39\x3d" + 
                              b"\x41\x45\x49\x4d\x51\x55\x59\\x5d" + 
                              b"\x61\x65\x69\x6d\x71\x75\x79\x7d" + 
                              b"\x81\x85\x89\x8d\x91\x95\x99\x9d" + 
                              b"\xa1\xa5\xa9\xad\xb1\xb5\xb9\xbd" +
                              b"\xc1\xc5\xc9\xcd\xd1\xd5\xd9\xdd" +
                              b"\xe1\xe5\xe9\xed\xf1\xf5\xf9\xfd][\x20-\x3f]")
    JALR_C_REG_EX = re.compile(b"[\x02\x82][\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f]")
    JR_C_REG_EX = re.compile(b"[\x02\x82][\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f]")

    POP_REG_EX = re.compile(b"[\x03\x83][\x00-\x7f][\x01\x11\x21\x31\x41\x51\x61\x71\x81\x91\xa1\xb1\xc1\xd1\xe1\xf1][\x00-\xff]")
    ARITHMETIC_REG_EX = re.compile(b"[\x13\x93][\x00-\xff]{3}")

    POP_C_REG_EX = re.compile(b"[\x02\x06\x0a\x0e\x12\x16\x1a\x1e" +
                              b"\x22\x26\x2a\x2e\x32\x36\x3a\x3e" +
                              b"\x42\x46\x4a\x4e\x52\x56\x5a\x5e" +
                              b"\x62\x66\x6a\x6e\x72\x76\x7a\x7e" +
                              b"\x82\x86\x8a\x8e\x92\x96\x9a\x9e" +
                              b"\xa2\xa6\xaa\xae\xb2\xb6\xba\xbe" +
                              b"\xc2\xc6\xca\xce\xd2\xd6\xda\xde" +
                              b"\xe2\xe6\xea\xee\xf2\xf6\xfa\xfe][\x60-\x7f]")
    ARITHMETIC_C_REG_EX = re.compile(b"[\x01\x05\x09\x0d\x11\x15\x19\x1d" +
                              b"\x21\x25\x29\x2d\x31\x35\x39\x3d" + 
                              b"\x41\x45\x49\x4d\x51\x55\x59\\x5d" + 
                              b"\x61\x65\x69\x6d\x71\x75\x79\x7d" + 
                              b"\x81\x85\x89\x8d\x91\x95\x99\x9d" + 
                              b"\xa1\xa5\xa9\xad\xb1\xb5\xb9\xbd" +
                              b"\xc1\xc5\xc9\xcd\xd1\xd5\xd9\xdd" +
                              b"\xe1\xe5\xe9\xed\xf1\xf5\xf9\xfd][\x80-\x9f]")    

class GadgetsCollection():
    def __init__(self, ret_gadget_regex, type_gadget_regex, md, output_filename, output_msg, exclude_regex = False):
        self.__ret_gadget_regex = ret_gadget_regex
        self.__type_gadget_regex = type_gadget_regex
        self.__md = md
        self.__exclude_regex = exclude_regex
        self.__output_filename = output_filename
        self.__output_msg = output_msg

        # key   -> gadget
        # value -> gadget's vaddr
        self.__gadgets = dict()

    def __is_ret(self, instruction):
        for pattern in self.__ret_gadget_regex:
            if pattern.match(instruction):
                return True
        return False

    def __is_type(self, instruction):
        if self.__exclude_regex == False:
            for pattern in self.__type_gadget_regex:
                if pattern.match(instruction):
                    return True
            return False
        else:
            for pattern in self.__type_gadget_regex:
                if pattern.match(instruction):
                    return False
            return True

    def __check_valid_gadget(self, gadget):
        # to be valid a gadget needs to be decoded completely
        # it also needs to be the right type of gadget

        decoded_size = 0
        corret_type = False

        for i in self.__md.disasm(gadget, 0x1000):
            bytecode = gadget[decoded_size : decoded_size + i.size]
            if self.__is_type(bytecode):
                corret_type = True

            decoded_size += i.size

        return (decoded_size == len(gadget) and corret_type == True)

    def __get_first_instruction(self, gadget):
        for i in self.__md.disasm(gadget, 0x1000):
            return gadget[:i.size]
        return None

    def find_gadgets(self, exec_sections, gadgets_max_len):
        print(f"Searching for {self.__output_msg} ...")

        for section in exec_sections:
            code = section["code"]
            vaddr = section["vaddr"]

            ret_gadgets = []
            for pattern in self.__ret_gadget_regex:
                ret_gadgets += [match.start() for match in re.finditer(pattern, code)]

            for ret_gadget in ret_gadgets:
                ret_start = ret_gadget
                try:
                    ret_len = next(self.__md.disasm(code[ret_start:], 0x1000)).size
                except:
                    continue # the gadget is not valid

                gadget_end = ret_gadget + ret_len

                for i in range(gadgets_max_len):
                    gadget_start = ret_start - i
                    gadget = code[gadget_start : gadget_end]

                    if self.__check_valid_gadget(gadget):
                        new_instruction = self.__get_first_instruction(gadget)

                        if new_instruction is None:
                            print("[Error] Bug found! Please report")
                            exit(0)

                        if i > 0 and self.__is_ret(new_instruction):
                            break # new gadget begins
                        
                        self.__gadgets[gadget] = vaddr + gadget_start

    def print_gadgets(self):
        with open(self.__output_filename, "w") as fout:
            fout.write(f"{self.__output_msg}\n")
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

    def get_size(self):
        return len(self.__gadgets)

class ROP():
    def __init__(self, binary):
        self.__binary  = binary
        self.__gadgets_max_len = 40

        # create output directory if it doesn't exist
        self.__out_dir_path = os.getcwd()
        self.__out_dir_path += "/results"
        if os.path.isdir(self.__out_dir_path) == False:
            os.mkdir(self.__out_dir_path)

        self.__arch_mode = self.__binary.get_arch_mode()
        self.__exec_sections = self.__binary.get_exec_sections()

        # change endianness if necesarry
        if self.__binary.get_endianness() == CS_MODE_BIG_ENDIAN:
            self.__exec_sections = [section[::-1] for section in self.__exec_sections] # convert to little endian

        # gadget collections

        self.__gadgets_collections_list = [
            # POP JOP gadgets
            GadgetsCollection(
                ret_gadget_regex  = [RISCV_CONSTANTS.JAL_REG_EX, RISCV_CONSTANTS.JALR_REG_EX],
                type_gadget_regex = [RISCV_CONSTANTS.POP_REG_EX],
                output_filename   = self.__out_dir_path + "/" + "uncompressed_pop_jop_gadgets.txt",
                output_msg        = "POP JOP gadgets",
                md                = Cs(CS_ARCH_RISCV, self.__arch_mode)
            ),

            # Arithmetic JOP gadgets
            GadgetsCollection(
                ret_gadget_regex  = [RISCV_CONSTANTS.JAL_REG_EX, RISCV_CONSTANTS.JALR_REG_EX],
                type_gadget_regex = [RISCV_CONSTANTS.ARITHMETIC_REG_EX],
                output_filename   = self.__out_dir_path + "/" + "uncompressed_arithmetic_jop_gadgets.txt",
                output_msg        = "Arithmetic JOP gadgets",
                md                = Cs(CS_ARCH_RISCV, self.__arch_mode)
            ),

            # Usual JOP gadgets
            GadgetsCollection(
                ret_gadget_regex  = [RISCV_CONSTANTS.JAL_REG_EX, RISCV_CONSTANTS.JALR_REG_EX],
                type_gadget_regex = [RISCV_CONSTANTS.POP_REG_EX, RISCV_CONSTANTS.ARITHMETIC_REG_EX],
                output_filename   = self.__out_dir_path + "/" + "uncompressed_jop_gadgets.txt",
                output_msg        = "JOP gadgets",
                md                = Cs(CS_ARCH_RISCV, self.__arch_mode),
                exclude_regex     = True
            ),

            # Compressed POP JOP gadgets
            GadgetsCollection(
                ret_gadget_regex  = [RISCV_CONSTANTS.JAL_REG_EX, RISCV_CONSTANTS.JALR_REG_EX, 
                                    RISCV_CONSTANTS.JAL_C_REG_EX, RISCV_CONSTANTS.JALR_C_REG_EX, RISCV_CONSTANTS.JR_C_REG_EX],
                type_gadget_regex = [RISCV_CONSTANTS.POP_REG_EX, RISCV_CONSTANTS.POP_C_REG_EX],
                output_filename   = self.__out_dir_path + "/" + "compressed_pop_jop_gadgets.txt",
                output_msg        = "Compressed POP JOP gadgets",
                md                = Cs(CS_ARCH_RISCV, CS_MODE_RISCVC)
            ),

            # Compressed Arithmetic JOP gadgets
            GadgetsCollection(
                ret_gadget_regex  = [RISCV_CONSTANTS.JAL_REG_EX, RISCV_CONSTANTS.JALR_REG_EX,
                                    RISCV_CONSTANTS.JAL_C_REG_EX, RISCV_CONSTANTS.JALR_C_REG_EX, RISCV_CONSTANTS.JR_C_REG_EX],
                type_gadget_regex = [RISCV_CONSTANTS.ARITHMETIC_REG_EX, RISCV_CONSTANTS.ARITHMETIC_C_REG_EX],
                output_filename   = self.__out_dir_path + "/" + "compressed_arithmetic_jop_gadgets.txt",
                output_msg        = "Compressed Arithmetic JOP gadgets",
                md                = Cs(CS_ARCH_RISCV, CS_MODE_RISCVC)
            ),

            # Compressed Usual JOP gadgets
            GadgetsCollection(
                ret_gadget_regex  = [RISCV_CONSTANTS.JAL_REG_EX, RISCV_CONSTANTS.JALR_REG_EX,
                                    RISCV_CONSTANTS.JAL_C_REG_EX, RISCV_CONSTANTS.JALR_C_REG_EX, RISCV_CONSTANTS.JR_C_REG_EX],
                type_gadget_regex = [RISCV_CONSTANTS.POP_REG_EX, RISCV_CONSTANTS.ARITHMETIC_REG_EX,
                                    RISCV_CONSTANTS.POP_C_REG_EX, RISCV_CONSTANTS.ARITHMETIC_C_REG_EX],
                output_filename   = self.__out_dir_path + "/" + "compressed_jop_gadgets.txt",
                output_msg        = "Compressed JOP gadgets",
                md                = Cs(CS_ARCH_RISCV, CS_MODE_RISCVC),
                exclude_regex     = True
            ),

            # ECALL gadgets
            GadgetsCollection(
                ret_gadget_regex  = [RISCV_CONSTANTS.ECALL_REG_EX],
                type_gadget_regex = [],
                output_filename   = self.__out_dir_path + "/" + "uncompressed_ecall_gadgets.txt",
                output_msg        = "ECALL gadgets",
                md                = Cs(CS_ARCH_RISCV, self.__arch_mode),
                exclude_regex     = True
            ),

            # Compressed ECALL gadgets
            GadgetsCollection(
                ret_gadget_regex  = [RISCV_CONSTANTS.ECALL_REG_EX],
                type_gadget_regex = [],
                output_filename   = self.__out_dir_path + "/" + "compressed_ecall_gadgets.txt",
                output_msg        = "Compressed ECALL gadgets",
                md                = Cs(CS_ARCH_RISCV, CS_MODE_RISCVC),
                exclude_regex     = True
            )
        ]

    def __find_gadgets(self):
        total_gadgets = 0

        for col in self.__gadgets_collections_list:
            col.find_gadgets(self.__exec_sections, RISCV_CONSTANTS.INSTRUCTION_LEN * self.__gadgets_max_len)
            total_gadgets += col.get_size()

        return total_gadgets

    def list_gadgets(self):
        total_gadgets = self.__find_gadgets()
        
        for col in self.__gadgets_collections_list:
            col.print_gadgets()

        print(f"{total_gadgets} gadgets found\n")

        print(f"Results are available at {self.__out_dir_path}")
