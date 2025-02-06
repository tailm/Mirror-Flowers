class ContextAnalyzer:
    def __init__(self):
        self.file_dependencies = {}
        self.global_variables = {}
        self.function_calls = {}
        self.class_hierarchy = {}
        
    def analyze_project_context(self, files):
        """分析项目整体上下文"""
        for file_path in files:
            self._analyze_file_context(file_path)
            
    def _analyze_file_context(self, file_path):
        """分析单个文件的上下文"""
        with open(file_path, 'r') as f:
            content = f.read()
            
        # 分析文件依赖
        self._analyze_dependencies(content, file_path)
        
        # 分析全局变量
        self._analyze_globals(content, file_path)
        
        # 分析函数调用关系
        self._analyze_function_calls(content, file_path)
        
        # 分析类继承关系
        self._analyze_class_hierarchy(content, file_path)
        
    def get_call_graph(self, function_name):
        """获取函数调用图"""
        call_graph = {
            'name': function_name,
            'calls': self.function_calls.get(function_name, []),
            'called_by': self._find_callers(function_name)
        }
        return call_graph
        
    def get_variable_scope(self, variable_name):
        """获取变量作用域"""
        if variable_name in self.global_variables:
            return {
                'type': 'global',
                'defined_in': self.global_variables[variable_name],
                'used_in': self._find_variable_usage(variable_name)
            }
        return None 