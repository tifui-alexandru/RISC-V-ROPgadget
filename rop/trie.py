class TrieNode():
    def __init__(self):
        self.is_end = False
        self.children = dict()

class Trie():
    def __init__(self):
        self.__root = TrieNode()
        self.__current_chain = ""
     
    def insert(self, chain):
        node = self.__root
 
        for op in chain:
            if op in node.children:
                node = node.children[op]
            else:
                new_node = TrieNode()
                node.children[op] = new_node
                node = new_node
         
        node.is_end = True

    def list_all(self):
        for chain in self.__dfs(self.__root):
            print(chain[-1::-1])

    def __dfs(self, node):
        if node.is_end:
            yield self.__current_chain
        
        for op, child in node.children.items():
            self.__current_chain += op
            yield from self.__dfs(child)
            self.__current_chain = self.__current_chain[:-1]