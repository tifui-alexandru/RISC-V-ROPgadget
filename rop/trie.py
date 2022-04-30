class TrieNode():
    def __init__(self):
        self.is_end = False
        self.children = dict()

class Trie():
    def __init__(self):
        self.__root = TrieNode()
        self.__current_string = ""
     
    def insert(self, word):
        node = self.__root
 
        for char in word:
            if char in node.children:
                node = node.children[char]
            else:
                new_node = TrieNode()
                node.children[char] = new_node
                node = new_node
         
        node.is_end = True

    def list_all_strings(self):
        for string in self.__dfs(self.__root):
            print(string)

    def __dfs(self, node):
        if node.is_end:
            yield self.__current_string
        
        for char, child in node.children.items():
            self.__current_string += char
            yield from self.__dfs(child)
            self.__current_string = self.__current_string[:-1]