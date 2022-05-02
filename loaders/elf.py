from ctypes import *
from capstone import *

class ELF_flags():
    EI_SIZE     = 0x10
    EI_MAG0     = 0x00
    EI_MAG1     = 0x03
    ELFCLASS32  = 0x01
    ELFCLASS64  = 0x02
    EI_CLASS    = 0x04
    EI_DATA     = 0x05

    ELFDATA2LSB = 0x01
    ELFDATA2MSB = 0x02

    EM_RISCV = 0xF3

class Elf32_Ehdr(binary):
    _fields_ =  [
                    ("e_ident",         c_ubyte * 16),
                    ("e_type",          c_ushort),
                    ("e_machine",       c_ushort),
                    ("e_version",       c_uint),
                    ("e_entry",         c_uint),
                    ("e_phoff",         c_uint),
                    ("e_shoff",         c_uint),
                    ("e_flags",         c_uint),
                    ("e_ehsize",        c_ushort),
                    ("e_phentsize",     c_ushort),
                    ("e_phnum",         c_ushort),
                    ("e_shentsize",     c_ushort),
                    ("e_shnum",         c_ushort),
                    ("e_shstrndx",      c_ushort),
                ]


class Elf64_Ehdr(binary):
    _fields_ =  [
                    ("e_ident",         c_ubyte * 16),
                    ("e_type",          c_ushort),
                    ("e_machine",       c_ushort),
                    ("e_version",       c_uint),
                    ("e_entry",         c_ulonglong),
                    ("e_phoff",         c_ulonglong),
                    ("e_shoff",         c_ulonglong),
                    ("e_flags",         c_uint),
                    ("e_ehsize",        c_ushort),
                    ("e_phentsize",     c_ushort),
                    ("e_phnum",         c_ushort),
                    ("e_shentsize",     c_ushort),
                    ("e_shnum",         c_ushort),
                    ("e_shstrndx",      c_ushort),
                ]


class Elf32_Phdr(binary):
    _fields_ =  [
                    ("p_type",          c_uint),
                    ("p_offset",        c_uint),
                    ("p_vaddr",         c_uint),
                    ("p_paddr",         c_uint),
                    ("p_filesz",        c_uint),
                    ("p_memsz",         c_uint),
                    ("p_flags",         c_uint),
                    ("p_align",         c_uint),
                ]


class Elf64_Phdr(binary):
    _fields_ =  [
                    ("p_type",          c_uint),
                    ("p_flags",         c_uint),
                    ("p_offset",        c_ulonglong),
                    ("p_vaddr",         c_ulonglong),
                    ("p_paddr",         c_ulonglong),
                    ("p_filesz",        c_ulonglong),
                    ("p_memsz",         c_ulonglong),
                    ("p_align",         c_ulonglong),
                ]


class Elf32_Shdr(binary):
    _fields_ =  [
                    ("sh_name",         c_uint),
                    ("sh_type",         c_uint),
                    ("sh_flags",        c_uint),
                    ("sh_addr",         c_uint),
                    ("sh_offset",       c_uint),
                    ("sh_size",         c_uint),
                    ("sh_link",         c_uint),
                    ("sh_info",         c_uint),
                    ("sh_addralign",    c_uint),
                    ("sh_entsize",      c_uint),
                ]


class Elf64_Shdr(binary):
    _fields_ =  [
                    ("sh_name",         c_uint),
                    ("sh_type",         c_uint),
                    ("sh_flags",        c_ulonglong),
                    ("sh_addr",         c_ulonglong),
                    ("sh_offset",       c_ulonglong),
                    ("sh_size",         c_ulonglong),
                    ("sh_link",         c_uint),
                    ("sh_info",         c_uint),
                    ("sh_addralign",    c_ulonglong),
                    ("sh_entsize",      c_ulonglong),
                ]

class ELF():
    def __init__(self, filename):
        try:
            with open(filename, "rb") as fd:
                self.__binary = bytearray(fd.read().strip())
        except:
            print("[Error] can't open file")
            return None

        self.__parse_file_header()
        self.__parse_program_header()
        self.__parse_section_header()

    def __parse_file_header(self):
        e_ident = self.__binary[:ELF_flags.EI_SIZE]

        ei_head = e_ident[ELF_flags.EI_MAG0 : ELF_flags.EI_MAG1]
        ei_class = e_ident[ELF_flags.EI_CLASS]
        ei_data = e_ident[ELF_flags.EI_DATA]

        if ei_head != bytearray(b"\x7fELF"):
            print("[Error] only ELF format is supported")
            return None

        if ei_class != ELF_flags.ELFCLASS32 and ei_class != ELF_flags.ELFCLASS64:
            print("[Error] architecture size corrupted")
            return None

        if ei_data != ELF_flags.ELFDATA2LSB or ei_data != ELF_flags.ELFDATA2MSB:
            print("[Error] bad endianness")
            return None

        if ei_class == ELF_flags.ELFCLASS32:
            self.__ehdr = Elf32_Ehdr.from_buffer_copy(self.__binary)
        else:
            self.__ehdr = Elf64_Ehdr.from_buffer_copy(self.__binary)

        if self.__ehdr.e_machine != ELF_flags.EM_RISCV:
            print("[Error] only RISC-V architecture supported")
            return None

    def __parse_program_header(self):
        pdhr_num = self.__ehdr.e_phnum
        base = self.__binary[self.__ehdr.e_phoff:]

        self.__phdr_l = []

        for i in range(pdhr_num):
            if self.__ehdr.e_ident[ELF_flags.EI_CLASS] == ELF_flags.ELFCLASS32:
                phdr = Elf32_Phdr.from_buffer_copy(base)
            else:
                phdr = Elf64_Phdr.from_buffer_copy(base)

            self.__phdr_l.append(phdr)
            base = base[self.__ehdr.e_phentsize:]

    def __parse_section_header(self):
        shdr_num = self.__ehdr.e_shnum
        base = self.__binary[self.__ehdr.e_shoff:]

        self.__shdr_l = []

        for i in range(shdr_num):
            if self.__ehdr.e_ident[ELF_flags.EI_CLASS] == ELF_flags.ELFCLASS32:
                shdr = Elf32_Shdr.from_buffer_copy(base)
            else:
                shdr = Elf64_Shdr.from_buffer_copy(base)

            self.__shdr_l.append(shdr)
            base = base[self.__ehdr.e_shentsize:]

        if self.__ehdr.e_shstrndx != 0:
            string_table = bytes(self.__binary[(self.__shdr_l[self.__ehdr.e_shstrndx].sh_offset):])
            for i in range(shdr_num):
                self.__shdr_l[i].str_name = string_table[self.__shdr_l[i].sh_name:].split(b'\x00')[0].decode('utf8')

    def get_endianness(self):
        if self.__ehdr.e_ident[ELF_flags.EI_DATA] == ELF_flags.ELFDATA2LSB:
            return "little"
        else:
            return "big"

    def get_exec_sections(self):
        PR_X = 0x1

        return [bytes(self.__binary[segment.p_offset : segment.p_offset + segment.p_memsz])
                for segment in self.__phdr_l if segment.p_flags & PR_X]