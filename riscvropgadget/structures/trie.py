class TrieNode():
    def __init__(self):
        self.end_address = None
        self.children = dict()

class Trie():
    def __init__(self):
        self.__root = TrieNode()
        self.__current_chain = []
        self.__empty = True
     
    def insert(self, chain, address):
        node = self.__root
        self.__empty = False
 
        for op in chain:
            if op in node.children:
                node = node.children[op]
            else:
                new_node = TrieNode()
                node.children[op] = new_node
                node = new_node
         
        if node.end_address is None:
            node.end_address = address

    def list_all(self):
        yield from self.__dfs(self.__root)

    def is_empty(self):
        return self.__empty

    def __dfs(self, node):
        if node.end_address is not None:
            yield {
                    "code":  self.__current_chain,
                    "vaddr": node.end_address
                  }
        
        for op, child in node.children.items():
            self.__current_chain.append(op)
            yield from self.__dfs(child)
            self.__current_chain = self.__current_chain[:-1]