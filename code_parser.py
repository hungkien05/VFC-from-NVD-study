import os
from tree_sitter import Language, Parser
import sys, resource

from lib import contains_full_range, find_start_end_lines_of_substring
resource.setrlimit(resource.RLIMIT_STACK, [0x10000000, resource.RLIM_INFINITY])
sys.setrecursionlimit(0x100000)

class BaseParser:
    def __init__(self, file_path):
        self.file_path = file_path
        # self.lang = lang
        # if self.file_path.endswith(".java"):
        #     # langParser = JavaParser(self.file_path)
        #     self.lang = "java"
        # elif self.file_path.endswith(".cs"):
        #     self.lang = "c_sharp"
        # elif self.file_path.endswith(".c"):
        #     self.lang = "c"
        # elif self.file_path.endswith(".js"):
        #     self.lang = "javascript"
        # elif self.file_path.endswith(".cpp"):
        #     self.lang = "cpp"
        # elif self.file_path.endswith(".py"):
        #     self.lang = "python"
        # else:
        #     self.lang = "others"
            
    def get_function_name(self, method_node):
        pass
    
    def get_function_name_only(self, method_node):
        pass
    
    def check_added(self,removed_lines, added_lines, start_line, end_line)-> bool:
        for line in removed_lines:
            if start_line <= line <= end_line:
                return False
        if start_line not in added_lines:
            return False
        return True
    
    def find_start_line(self, method_source):
        pass
    
    def check_removed(self,removed_lines, start_line)-> bool:
        if start_line in removed_lines:
            return True
        return False
    def prepare_tree_sitter(self, lang):
        # Language.build_library(f'tree-sitter_vendor/tree-sitter-{lang}/my-languages.so',[f'tree-sitter_vendor/tree-sitter-{lang}'])
        LANGUAGE = Language(f'tree-sitter_vendor/tree-sitter-{lang}/my-languages.so', lang)
        self.tree_sitterParser = Parser()
        self.tree_sitterParser.set_language(LANGUAGE)
        
    def get_functions(self,parent_file_content,fixed_file_content, lines):
        
        # self.prepare_tree_sitter(self.lang)
        res = self.search_functions(parent_file_content,fixed_file_content, lines)
        return res
    
    def find_method_nodes(self,node, whole_file_content):
        method_nodes = []
        if node.type in ['method_declaration', #java, c#, 
                         'method_definition',  #js
                         'member_function_definition', #cpp
                         'function_definition', #cpp
                         'function_declaration', #js
                         ]:
             
            method_source = node.text.decode('utf-8')
            if "@Override\n    public void use(String resource, XWikiContext context)" in method_source:
                a=1
            start_line, end_line = find_start_end_lines_of_substring(whole_file_content, method_source)
            start_offset = self.find_start_line(method_source)
            if end_line ==None:
                start_line = node.start_point[0]  
                end_line = node.end_point[0]
            start_line += start_offset-1
            func_id = self.get_function_name_only(node)
            method_nodes.append((node, method_source, start_line, end_line, func_id))
        for child in node.children:
            method_nodes.extend(self.find_method_nodes(child, whole_file_content))
        return method_nodes
    
    def search_func_by_name(self, target_name, method_nodes):
        for node,_, _, _,_ in method_nodes:
            current_func_name = self.get_function_name_only(node)
            if current_func_name == target_name:
                return node
        return None
    
    def search_functions(self,parent_file_content,fixed_file_content, lines_hunks): 
        self.parent_file_content = parent_file_content
        self.fixed_file_content =fixed_file_content
        f = open("log_code_parser.txt", "a")
        byte_src = bytes(parent_file_content, "utf8")
        tree = self.tree_sitterParser.parse(byte_src)
        root_node = tree.root_node
        # Find all method nodes
        parent_method_nodes = self.find_method_nodes(root_node, parent_file_content)
        
        #fixed
        byte_src = bytes(fixed_file_content, "utf8")
        tree = self.tree_sitterParser.parse(byte_src)
        root_node = tree.root_node
        # Find all method nodes
        fixed_method_nodes = self.find_method_nodes(root_node,fixed_file_content)

        # Filter methods based on the provided line numbers
        methods_for_lines = []
        results = set()
        non_vul_methods = []
        # for node, start_line, end_line in parent_method_nodes:
        #     method_source = byte_src[node.start_byte:node.end_byte].decode("utf-8")
        #     check = False
        #     for line_number in lines:
        #         if start_line <= line_number <= end_line:
        #             methods_for_lines.append((method_source,0))
        #             check = True
        #             break
            # if not check:
            #     non_vul_methods.append((method_source,0))

        # return set(methods_for_lines)
        
        for lines_hunk in lines_hunks:
            # print(lines_hunk)
            removed_lines = lines_hunk[0]
            added_lines = lines_hunk[1]
            parent_source = None
            check_parent = False
            fixed_source = None
            check_fixed = False
            for node,method_source, start_line, end_line, func_id in parent_method_nodes:
                parent_func_names = []
                #case 1
                for line_no in removed_lines:
                    if start_line <= line_no <= end_line: # check if all removed lines are inside this parent function
                        current_func_name = self.get_function_name_only(node)
                        # if "public void use(String resource, XWikiContext context)" in method_source:
                        #         a=1
                        parent_source = method_source
                        fixed_method_node = self.search_func_by_name(current_func_name, fixed_method_nodes)
                        if fixed_method_node == None:
                            if contains_full_range(removed_lines, start_line, end_line) or self.check_removed(removed_lines, start_line):
                                results.add((method_source,3,func_id)) # removed_func
                            else:
                                results.add((method_source,1,func_id)) # vuln parent
                                f.write(f"{current_func_name}: cannot find fixed\n")
                        else:
                            results.add((method_source,1, func_id)) # vuln parent
                            fixed_method_source = fixed_method_node.text.decode('utf-8')
                            results.add((fixed_method_source,2, func_id)) #fixed
                        f.write(f"{current_func_name}: found fixed\n")
                        check_parent = True
                        # break
            for node,method_source, start_line, end_line, func_id in fixed_method_nodes:
                fixed_func_name = self.get_function_name_only(node)
                fixed_func_names = []
                check_fixed = False
                for line_no in added_lines:
                    if start_line <= line_no <= end_line: # check if all added lines are inside this fixed function
                        current_func_name = self.get_function_name_only(node)
                        parent_method_node = self.search_func_by_name(current_func_name, parent_method_nodes)
                        if parent_method_node == None:
                            if self.check_added(removed_lines, added_lines, start_line, end_line):
                                results.add((method_source,4, func_id)) #added func
                            else:
                                results.add((method_source,2, func_id)) #  fixed
                                f.write(f"{current_func_name}: cannot find parent\n")
                        else:
                            results.add((method_source,2, func_id)) #  fixed
                            parent_method_source = parent_method_node.text.decode('utf-8')
                            results.add((parent_method_source,1, func_id)) #vuln parent
                        check_fixed = True
                        f.write(f"{current_func_name}: found parent\n")
        for node,method_source, start_line, end_line,func_id in fixed_method_nodes:
            if (method_source,2, func_id) not in results and (method_source,4, func_id) not in results:
                results.add((method_source,0, func_id)) #unchanged
        f.close()
        return results
               
    
    def search_functions_simple(self,file_source_code, lines):
        # print(source_code)
        # print(self.file_path)
        byte_src = bytes(file_source_code, "utf8")
        tree = self.tree_sitterParser.parse(byte_src)
        root_node = tree.root_node
        # Find all method nodes
        method_nodes = self.find_method_nodes(root_node, file_source_code)

        # Filter methods based on the provided line numbers
        methods_for_lines = []
        non_vul_methods = []
        for node, method_source, start_line, end_line, _ in method_nodes:
            # self.get_function_name(node)
            # method_source = byte_src[node.start_byte:node.end_byte].decode("utf-8")
            check = False
            for line_number in lines:
                if start_line <= line_number <= end_line:
                    methods_for_lines.append(method_source)
                    check = True
                    break
            # if not check:
            #     non_vul_methods.append((method_source,0))

        return set(methods_for_lines)
        # return set(methods_for_lines+non_vul_methods)

class JavaParser(BaseParser):
    def __init__(self, file_path= None):
        super().__init__(file_path)
        self.prepare_tree_sitter()
        self.lang = "java"
    def prepare_tree_sitter(self,):
        lang ="java"
        # Language.build_library(f'tree-sitter_vendor/tree-sitter-{lang}/my-languages.so',[f'tree-sitter_vendor/tree-sitter-{lang}'])
        LANGUAGE = Language(f'tree-sitter_vendor/tree-sitter-{lang}/my-languages.so', lang)
        self.tree_sitterParser = Parser()
        self.tree_sitterParser.set_language(LANGUAGE)
    def get_function_name(self, method_node):
        if method_node.type == 'method_declaration':
            method_name = ''
            output = ""
            params = []
            for child in method_node.children:
                if child.type == 'identifier':
                    method_name = child.text.decode('utf8')
                    output +=f"{method_name}_"
                elif child.type == 'formal_parameters':
                    # Iterate over each parameter within the formal parameters
                    for param in child.children:
                        if param.type == 'formal_parameter':
                            param_type = None
                            param_name = None
                            for param_child in param.children:
                                if param_child.type == 'type_identifier':
                                    param_type = param_child.text.decode('utf8')
                                    if len(param_type) >0:
                                        output += f"{param_type}_"
                                elif param_child.type == 'identifier':
                                    param_name = param_child.text.decode('utf8')
                                    if len(param_name) >0:
                                        output += f"{param_name}_"
                            # if param_type and param_name:
                            #     params.append((param_type, param_name))
            
            # print(f"Method Name: {method_name}, Parameters: {params}")
            return output
        
    def get_function_name_only(self, method_node):
        if method_node.type == 'method_declaration':
            method_name = ''
            output = ""
            params = []
            for child in method_node.children:
                if child.type == 'identifier':
                    method_name = child.text.decode('utf8')
        return method_name  
                     
    def find_start_line(self, method_source):
        lines = method_source.split('\n')
        # Initialize variables to track the line number
        line_number = 0
        declaration_line = 0

        for line in lines:
            line_number += 1  # Increment line number for each line we process
            # Check if the line contains the opening brace of the function body
            if '{' in line:
                declaration_line = line_number
                # Check if opening brace is not the first character, assuming there could be a function declaration before it on the same line
                if line.strip().index('{') > 0:
                    break  # Assume the declaration is on this line if there are characters before the opening brace
                # If the opening brace is the first character, the declaration was on the previous line
                else:
                    declaration_line -= 1
                    break
        return declaration_line
    
class PythonParser(BaseParser):
    def __init__(self, file_path):
        super().__init__(file_path)
        self.prepare_tree_sitter()
        
    def prepare_tree_sitter(self, ):
        self.lang =  "python"
        # Language.build_library(f'tree-sitter_vendor/tree-sitter-{lang}/my-languages.so',[f'tree-sitter_vendor/tree-sitter-{lang}'])
        LANGUAGE = Language(f'tree-sitter_vendor/tree-sitter-{self.lang }/my-languages.so', self.lang)
        self.tree_sitterParser = Parser()
        self.tree_sitterParser.set_language(LANGUAGE)
    def get_function_name(self, method_node):
        # for child in method_node.children:
        #     if child.type == 'identifier':
        #         func_name = child.text.decode('utf8')
        #         print(f"func_name = {func_name}")
        #         return func_name
        
        function_name = ""
        parameters = []

        # Find the function name and parameter list nodes
        for child in method_node.children:
            if child.type == 'identifier':
                function_name = child.text.decode('utf8')
            elif child.type == 'parameters':
                for param in child.children:
                    if param.type == 'identifier':
                        parameters.append(param.text.decode('utf8'))

        return function_name + "_" + "_".join(parameters)
    
    def get_function_name_only(self, method_node):
        # for child in method_node.children:
        #     if child.type == 'identifier':
        #         func_name = child.text.decode('utf8')
        #         print(f"func_name = {func_name}")
        #         return func_name
        
        function_name = ""
        parameters = []

        # Find the function name and parameter list nodes
        for child in method_node.children:
            if child.type == 'identifier':
                function_name = child.text.decode('utf8')

        return function_name
    
    def find_start_line(self, method_source):
        lines = method_source.split('\n')
        line_number = 0
        declaration_line = 0
        for line in lines:
            line_number += 1  
            if ':' in line:
                declaration_line = line_number
                break
        return declaration_line
class CPPParser(BaseParser):
    def __init__(self, file_path):
        super().__init__(file_path)
        self.prepare_tree_sitter()
        
    def prepare_tree_sitter(self, ):
        self.lang = "cpp"
        # Language.build_library(f'tree-sitter_vendor/tree-sitter-{lang}/my-languages.so',[f'tree-sitter_vendor/tree-sitter-{lang}'])
        LANGUAGE = Language(f'tree-sitter_vendor/tree-sitter-{self.lang}/my-languages.so', self.lang)
        self.tree_sitterParser = Parser()
        self.tree_sitterParser.set_language(LANGUAGE)
    def get_function_name(self, method_node):
        function_name = None
        parameters = []

        # Extract function name and parameters
        for child in method_node.children:
            if child.type == "declarator":
                for grandchild in child.children:
                    if grandchild.type == "identifier":
                        function_name = grandchild.text.decode("utf8")
                    elif grandchild.type == "parameter_list":
                        # Collect all parameters and join them by dash
                        param_nodes = grandchild.named_children
                        for param_node in param_nodes:
                            if param_node.type == "parameter_declaration":
                                parameter_text = param_node.text.decode("utf8").replace(" ", "")
                                parameters.append(parameter_text)
        if function_name == None:
            return ""
        return function_name + "_" + "_".join(parameters)
        
    def get_function_name_only(self, method_node):
        function_name = None
        parameters = []

        # Extract function name and parameters
        for child in method_node.children:
            if child.type == "declarator":
                for grandchild in child.children:
                    if grandchild.type == "identifier":
                        function_name = grandchild.text.decode("utf8")
        if function_name == None:
            return ""
        return function_name
    
    
    def find_start_line(self, method_source):
        lines = method_source.split('\n')
        line_number = 0
        declaration_line = 0
        for line in lines:
            line_number += 1  
            if '{' in line:
                declaration_line = line_number
                if line.strip().index('{') > 0:
                    break
                else:
                    declaration_line -= 1
                    break
        return declaration_line
class JavaScriptParser(BaseParser):
    def __init__(self, file_path):
        super().__init__(file_path)
        self.prepare_tree_sitter()
        
    def prepare_tree_sitter(self, ):
        self.lang =  "javascript"
        # Language.build_library(f'tree-sitter_vendor/tree-sitter-{lang}/my-languages.so',[f'tree-sitter_vendor/tree-sitter-{lang}'])
        LANGUAGE = Language(f'tree-sitter_vendor/tree-sitter-{self.lang}/my-languages.so',self.lang)
        self.tree_sitterParser = Parser()
        self.tree_sitterParser.set_language(LANGUAGE)
    def get_function_name(self, method_node):
        function_name = ""
        parameters = []

        # Navigate to the function name and parameter list
        for child in method_node.children:
            if child.type == 'identifier':
                function_name = child.text.decode('utf8')
            elif child.type == 'formal_parameters':
                for param in child.children:
                    if param.type == 'identifier':
                        parameters.append(param.text.decode('utf8'))

        return function_name + "_" + "_".join(parameters)
    
    def get_function_name_only(self, method_node):
        function_name = ""
        parameters = []

        # Navigate to the function name and parameter list
        for child in method_node.children:
            if child.type == 'identifier':
                function_name = child.text.decode('utf8')

        return function_name

    def find_start_line(self, method_source):
        lines = method_source.split('\n')
        line_number = 0
        declaration_line = 0
        for line in lines:
            line_number += 1  
            if '{' in line:
                declaration_line = line_number
                if line.strip().index('{') > 0:
                    break
                else:
                    declaration_line -= 1
                    break
        return declaration_line
    
class CSharpParser(BaseParser):
    def __init__(self, file_path):
        super().__init__(file_path)
        self.prepare_tree_sitter()
        
    def prepare_tree_sitter(self, ):
        self.lang =  "c_sharp"
        # Language.build_library(f'tree-sitter_vendor/tree-sitter-{lang}/my-languages.so',[f'tree-sitter_vendor/tree-sitter-{lang}'])
        LANGUAGE = Language(f'tree-sitter_vendor/tree-sitter-{self.lang}/my-languages.so',self.lang)
        self.tree_sitterParser = Parser()
        self.tree_sitterParser.set_language(LANGUAGE)
    def get_function_name(self, method_node):
        method_name = ""
        parameters = []

        # Find the function name and parameter list nodes
        for child in method_node.children:
            if child.type == 'identifier':
                method_name = child.text.decode('utf8')
            elif child.type == 'parameter_list':
                for parameter in child.children:
                    if parameter.type == 'parameter':
                        # Assuming parameter has an identifier child
                        param_name = ''.join([n.text.decode('utf8') for n in parameter.children if n.type == 'identifier'])
                        parameters.append(param_name)
    
        return method_name + "_" + "_".join(parameters)
    
    def get_function_name_only(self, method_node):
        method_name = ""
        parameters = []

        # Find the function name and parameter list nodes
        for child in method_node.children:
            if child.type == 'identifier':
                method_name = child.text.decode('utf8')
    
        return method_name
    
    def find_start_line(self, method_source):
        lines = method_source.split('\n')
        line_number = 0
        declaration_line = 0
        for line in lines:
            line_number += 1  
            if '{' in line:
                declaration_line = line_number
                if line.strip().index('{') > 0:
                    break
                else:
                    declaration_line -= 1
                    break
        return declaration_line
    
class CParser(BaseParser):
    def __init__(self, file_path):
        super().__init__(file_path)
        self.prepare_tree_sitter()
        
    def prepare_tree_sitter(self, ):
        self.lang = "c"
        # Language.build_library(f'tree-sitter_vendor/tree-sitter-{lang}/my-languages.so',[f'tree-sitter_vendor/tree-sitter-{lang}'])
        LANGUAGE = Language(f'tree-sitter_vendor/tree-sitter-{self.lang}/my-languages.so', "c")
        self.tree_sitterParser = Parser()
        self.tree_sitterParser.set_language(LANGUAGE)
    def get_function_name(self, method_node):
        function_name = None
        parameters = []
        
        for child in method_node.children:
            if child.type == "function_declarator":
                for grandchild in child.children:
                    if grandchild.type == "identifier":
                        function_name = grandchild.text.decode("utf8")
                    elif grandchild.type == "parameter_list":
                        # Collect all parameters and join them by dash
                        param_nodes = grandchild.named_children
                        for param_node in param_nodes:
                            if param_node.type == "parameter_declaration":
                                parameter_text = param_node.text.decode("utf8").replace(" ", "")
                                parameters.append(parameter_text)
        if function_name == None:
            return ""
        return function_name + "_" + "_".join(parameters)
    
    def get_function_name_only(self, method_node):
        function_name = None
        parameters = []
        
        for child in method_node.children:
            if child.type == "function_declarator":
                for grandchild in child.children:
                    if grandchild.type == "identifier":
                        function_name = grandchild.text.decode("utf8")
        if function_name == None:
            return ""
        return function_name
        
    def find_start_line(self, method_source):
        lines = method_source.split('\n')
        line_number = 0
        declaration_line = 0
        for line in lines:
            line_number += 1  
            if '{' in line:
                declaration_line = line_number
                if line.strip().index('{') > 0:
                    break
                else:
                    declaration_line -= 1
                    break
        return declaration_line
    
def get_origin(label):
    if label ==0:
        origin = "unchanged" #parent
    elif label==1:
        origin = "vuln" #parent
    elif label==2:
        origin = "fixed"  #vfc
    elif label==3:
        origin = "removed" #paren t
    else:
        origin = "added" #vfc
    return origin
    
def find_lang(file_path):
    if file_path.endswith(".java"):
        # return None
        lang = "java"
        parser = JavaParser(file_path=file_path)
    elif file_path.endswith(".cs"):
        lang = "c_sharp"
        parser = CSharpParser(file_path)
    elif file_path.endswith(".c"):
        lang = "c"
        parser = CParser(file_path)
    elif file_path.endswith(".js"):
        lang = "javascript"
        parser = JavaScriptParser(file_path)
    elif file_path.endswith(".cpp"):
        lang = "cpp"
        parser = CPPParser(file_path)
    elif file_path.endswith(".py"):
        lang = "python"
        parser = PythonParser(file_path)
    else:
        lang = "others" #todo: deal with this
        return None
    return parser


if __name__ == "__main__":
    missing_nodes = []
    # res=None
    def traverse_tree(node):
        for n in node.children:
            if n.is_missing: 
                missing_nodes.append(n)
            if node.type == 'function_definition':
                res = parser.get_function_name(node)
                print(res)
            traverse_tree(n)
    
    with open("dummy_src.txt", "r") as f:
        src = f.read()
    file_path = "siu.c"
    # parser = BaseParser(file_path)
    parser = find_lang(file_path)
    # res = parser.get_functions(src,src, [([7], [8])])
    method_source = """public int AddNumbers(int a, int b)
        {
            return a + b;
        }
    """
    # res = parser.find_start_line(method_source)
    # res = parser.search_functions_simple(src, [105])
    
    
    #test get_function_name
    function_code = """
int add(int a, int b) {
    return a + b;
}

void printHello() {
    printf("Hello, World!");
}

class Example {
public:
    void method(int x, int y);
};

void Example::method(int x, int y) {
    // Some code
}
"""
    # parser.prepare_tree_sitter()
    
    tree = parser.tree_sitterParser.parse(bytes(function_code, 'utf8'))
    root_node = tree.root_node
    for node in root_node.children:
        if node.type == 'method_declaration':
            res = parser.get_function_name(node)
    
    traverse_tree(root_node)
    
    
    # stack = []
    # stack.append(root_node)
    # res = None
    # while res == None:
    #     current_node = stack.pop()
    #     # current_node.visited = True
    #     for node in current_node.children:
    #         try:
    #             # if node.visited == False:
    #                 stack.append(node)
    #         except Exception:
    #             a=1
    #         if node.type == 'method_declaration':
    #             res = parser.get_function_name(node)
        
    print(res)