from trie import *

class RISCV_CONSTANTS():
    INSTRUCTION_LEN = 4

class ROP():
    def __init__(self, binary):
        self.__binary  = binary
        self.__gadgets = Trie()
        self.__gadgets_max_len = 10

    def __is_gadget_link(self, instruction, gadget_links):
        pass # to do

    def __scan_binary(self):
        if self.__binary.get_endianness() == "little":
            gadget_links = [] # to be derermined
        else:
            gadget_links = [] # to be determined

        exec_sections = self.__binary.get_exec_sections()

        for section in exec_sections:
            current_chain = []

            for instruction_end in range(len(section), 0, -RISCV_CONSTANTS.INSTRUCTION_LEN):
                instruction = section[instruction_end - RISCV_CONSTANTS.INSTRUCTION_LEN : instruction_end]

                if self.__is_gadget_link(instruction, gadget_links):
                    current_chain = []
                
                if len(current_chain) < self.__gadgets_max_len:
                    current_chain.append(instruction)
                    self.__gadgets.insert(current_chain)

    def list_gadgets(self):
        pass