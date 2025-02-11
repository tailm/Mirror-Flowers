import ast
from typing import Dict, Set, List, Optional, Union
from pathlib import Path
from dataclasses import dataclass

@dataclass
class AnalyzerConfig:
    max_workers: int = 4  # 并行处理的最大线程数
    ignore_patterns: List[str] = None  # 要忽略的文件模式
    follow_imports: bool = True  # 是否分析导入的模块
    max_depth: int = 3  # 分析的最大深度
    encoding: str = 'utf-8'  # 文件编码

class CodeAnalyzer:
    def __init__(self, config: Optional[AnalyzerConfig] = None):
        self.config = config or AnalyzerConfig()
        self.dependencies: Dict[str, Set[str]] = {}
        self.globals: Dict[str, Set[str]] = {}
        self.function_calls: Dict[str, Set[str]] = {}
        self.class_hierarchy: Dict[str, List[str]] = {}
        self.variable_usages: Dict[str, Set[str]] = {}  # 存储变量使用位置

    def _analyze_dependencies(self, content: str, file_path: str) -> None:
        """分析文件的导入依赖关系"""
        tree = ast.parse(content)
        
        class ImportVisitor(ast.NodeVisitor):
            def __init__(self, analyzer, file_path):
                self.analyzer = analyzer
                self.file_path = file_path
                self.aliases = {}  # 记录导入别名
                
            def visit_Import(self, node):
                for name in node.names:
                    self.analyzer.dependencies.setdefault(self.file_path, set()).add(name.name)
                    if name.asname:
                        self.aliases[name.asname] = name.name
                        
            def visit_ImportFrom(self, node):
                module = node.module if node.module else ''
                for name in node.names:
                    full_name = f"{module}.{name.name}" if module else name.name
                    self.analyzer.dependencies.setdefault(self.file_path, set()).add(full_name)
                    if name.asname:
                        self.aliases[name.asname] = full_name
                        
            def visit_Name(self, node):
                # 检查是否使用了导入的别名
                if node.id in self.aliases:
                    self.analyzer.dependencies.setdefault(self.file_path, set()).add(self.aliases[node.id])
                self.generic_visit(node)
        
        visitor = ImportVisitor(self, file_path)
        visitor.visit(tree)

    def _analyze_globals(self, content: str, file_path: str) -> None:
        """分析全局变量"""
        tree = ast.parse(content)
        
        class GlobalVisitor(ast.NodeVisitor):
            def __init__(self, analyzer, file_path):
                self.analyzer = analyzer
                self.file_path = file_path
                self.current_scope = None
                
            def visit_Module(self, node):
                old_scope = self.current_scope
                self.current_scope = 'module'
                self.generic_visit(node)
                self.current_scope = old_scope
                
            def visit_Global(self, node):
                for name in node.names:
                    self.analyzer.globals.setdefault(self.file_path, set()).add(name)
                    
            def visit_Assign(self, node):
                if self.current_scope == 'module' and isinstance(node.targets[0], ast.Name):
                    self.analyzer.globals.setdefault(self.file_path, set()).add(node.targets[0].id)
                self.generic_visit(node)
        
        visitor = GlobalVisitor(self, file_path)
        visitor.visit(tree)

    def _analyze_function_calls(self, content: str, file_path: str) -> None:
        """分析函数调用关系"""
        tree = ast.parse(content)
        
        class FunctionCallVisitor(ast.NodeVisitor):
            def __init__(self, analyzer, file_path):
                self.analyzer = analyzer
                self.file_path = file_path
                self.current_function = None
                self.current_class = None
                
            def visit_ClassDef(self, node):
                old_class = self.current_class
                self.current_class = node.name
                self.generic_visit(node)
                self.current_class = old_class
                
            def visit_FunctionDef(self, node):
                old_function = self.current_function
                if self.current_class:
                    self.current_function = f"{self.current_class}.{node.name}"
                else:
                    self.current_function = node.name
                self.generic_visit(node)
                self.current_function = old_function
                
            def visit_Call(self, node):
                if not self.current_function:
                    return
                
                caller = f"{self.file_path}:{self.current_function}"
                
                if isinstance(node.func, ast.Name):
                    callee = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    # 处理方法调用
                    if isinstance(node.func.value, ast.Name):
                        callee = f"{node.func.value.id}.{node.func.attr}"
                    else:
                        callee = node.func.attr
                else:
                    return
                    
                self.analyzer.function_calls.setdefault(caller, set()).add(callee)
                self.generic_visit(node)
        
        visitor = FunctionCallVisitor(self, file_path)
        visitor.visit(tree)

    def _analyze_class_hierarchy(self, content: str, file_path: str) -> None:
        """分析类继承关系"""
        tree = ast.parse(content)
        
        class ClassVisitor(ast.NodeVisitor):
            def __init__(self, analyzer, file_path):
                self.analyzer = analyzer
                self.file_path = file_path
                self.current_module = None
                
            def visit_Module(self, node):
                for imp in node.body:
                    if isinstance(imp, ast.ImportFrom):
                        self.current_module = imp.module
                self.generic_visit(node)
                
            def visit_ClassDef(self, node):
                class_name = f"{self.file_path}:{node.name}"
                bases = []
                for base in node.bases:
                    if isinstance(base, ast.Name):
                        bases.append(base.id)
                    elif isinstance(base, ast.Attribute):
                        # 处理完整的模块路径
                        parts = []
                        current = base
                        while isinstance(current, ast.Attribute):
                            parts.append(current.attr)
                            current = current.value
                        if isinstance(current, ast.Name):
                            parts.append(current.id)
                        bases.append('.'.join(reversed(parts)))
                if bases:
                    self.analyzer.class_hierarchy[class_name] = bases
        
        visitor = ClassVisitor(self, file_path)
        visitor.visit(tree)

    def _analyze_variable_usage(self, content: str, file_path: str) -> None:
        """分析变量的使用位置"""
        tree = ast.parse(content)
        
        class VariableVisitor(ast.NodeVisitor):
            def __init__(self, analyzer, file_path):
                self.analyzer = analyzer
                self.file_path = file_path
                self.current_function = None
                self.current_class = None
                
            def visit_ClassDef(self, node):
                old_class = self.current_class
                self.current_class = node.name
                self.generic_visit(node)
                self.current_class = old_class
                
            def visit_FunctionDef(self, node):
                old_function = self.current_function
                scope = f"{self.current_class}.{node.name}" if self.current_class else node.name
                self.current_function = scope
                self.generic_visit(node)
                self.current_function = old_function
                
            def visit_Name(self, node):
                if isinstance(node.ctx, (ast.Load, ast.Store)):
                    scope = f"{self.file_path}:{self.current_function}" if self.current_function else self.file_path
                    self.analyzer.variable_usages.setdefault(node.id, set()).add(scope)
                self.generic_visit(node)
                
            def visit_Attribute(self, node):
                if isinstance(node.ctx, (ast.Load, ast.Store)) and isinstance(node.value, ast.Name):
                    if node.value.id == 'self' and self.current_class:
                        # 记录实例变量
                        var_name = f"{self.current_class}.{node.attr}"
                        scope = f"{self.file_path}:{self.current_function}"
                        self.analyzer.variable_usages.setdefault(var_name, set()).add(scope)
                self.generic_visit(node)
        
        visitor = VariableVisitor(self, file_path)
        visitor.visit(tree)

    def get_file_dependencies(self, file_path: str) -> set:
        """获取指定文件的依赖"""
        return self.dependencies.get(file_path, set())

    def get_file_globals(self, file_path: str) -> set:
        """获取指定文件的全局变量"""
        return self.globals.get(file_path, set())

    def get_function_calls(self, function_name: str) -> set:
        """获取指定函数调用的其他函数"""
        return self.function_calls.get(function_name, set())

    def get_class_bases(self, class_name: str) -> list:
        """获取指定类的父类"""
        return self.class_hierarchy.get(class_name, [])

    def get_variable_usages(self, variable_name: str) -> set:
        """获取变量的所有使用位置"""
        return self.variable_usages.get(variable_name, set())

    def analyze_file(self, content: str, file_path: Union[str, Path]) -> None:
        """分析单个文件的所有关系
        
        Args:
            content (str): 文件内容
            file_path (Union[str, Path]): 文件路径
            
        Raises:
            SyntaxError: 当文件包含语法错误时
            Exception: 其他分析错误
        """
        if isinstance(file_path, Path):
            file_path = str(file_path)
        try:
            # 分析文件依赖
            self._analyze_dependencies(content, file_path)
            
            # 分析全局变量
            self._analyze_globals(content, file_path)
            
            # 分析函数调用关系
            self._analyze_function_calls(content, file_path)
            
            # 分析类继承关系
            self._analyze_class_hierarchy(content, file_path)
            
            # 分析变量使用位置
            self._analyze_variable_usage(content, file_path)
        except SyntaxError:
            print(f"语法错误: {file_path}")
        except Exception as e:
            print(f"分析错误 {file_path}: {str(e)}")

    def get_file_analysis(self, file_path: str) -> dict:
        """获取指定文件的完整分析结果"""
        return {
            'dependencies': self.get_file_dependencies(file_path),
            'globals': self.get_file_globals(file_path),
            'function_calls': {
                caller: self.get_function_calls(caller)
                for caller in self.function_calls
                if caller.startswith(f"{file_path}:")
            },
            'class_hierarchy': {
                class_name: self.get_class_bases(class_name)
                for class_name in self.class_hierarchy
                if class_name.startswith(f"{file_path}:")
            }
        } 