from typing import List, Dict, Any
import ast
from phply.phpast import *
import esprima

class PHPASTVisitor:
    def __init__(self):
        self.issues = []
        
    def visit(self, nodes: List[Any]) -> None:
        """访问PHP AST节点"""
        if not isinstance(nodes, list):
            nodes = [nodes]
            
        for node in nodes:
            if node is None:
                continue
            method = f'visit_{node.__class__.__name__}'
            visitor = getattr(self, method, self.generic_visit)
            visitor(node)
        
    def generic_visit(self, node: Any) -> None:
        """通用访问方法"""
        for field in node.__dict__.values():
            if isinstance(field, (list, tuple)):
                for item in field:
                    if hasattr(item, '__dict__'):
                        self.visit(item)
            elif hasattr(field, '__dict__'):
                self.visit(field)
                    
    def visit_FunctionCall(self, node: FunctionCall) -> None:
        """访问函数调用"""
        if isinstance(node.name, str):
            func_name = node.name
        elif hasattr(node.name, 'name'):
            func_name = node.name.name
        else:
            func_name = str(node.name)
            
        if self._is_dangerous_function(func_name):
            self.issues.append({
                "type": "dangerous_function",
                "description": f"使用了危险函数 {func_name}",
                "severity": "high",
                "line": node.lineno if hasattr(node, 'lineno') else None
            })
        self.generic_visit(node)
        
    def _is_dangerous_function(self, func_name: str) -> bool:
        """检查是否为危险函数"""
        dangerous_functions = {
            'eval', 'exec', 'system', 'shell_exec', 'passthru',
            'file_get_contents', 'file_put_contents', 'fopen',
            'mysql_query', 'mysqli_query'
        }
        return func_name in dangerous_functions

class TypeScriptASTVisitor:
    def __init__(self):
        self.issues = []
        
    def visit(self, node: esprima.nodes.Node) -> None:
        """访问TypeScript/JavaScript AST节点"""
        if not node:
            return
            
        method = f'visit_{node.type}'
        visitor = getattr(self, method, self.generic_visit)
        visitor(node)
        
        # 访问子节点
        for key, value in node.__dict__.items():
            if isinstance(value, list):
                for item in value:
                    if isinstance(item, esprima.nodes.Node):
                        self.visit(item)
            elif isinstance(value, esprima.nodes.Node):
                self.visit(value)
                
    def visit_CallExpression(self, node: esprima.nodes.Node) -> None:
        """访问函数调用"""
        func_name = self._get_function_name(node.callee)
        if self._is_dangerous_function(func_name):
            self.issues.append({
                "type": "dangerous_function",
                "description": f"使用了危险函数 {func_name}",
                "severity": "high",
                "line": node.loc.start.line if hasattr(node, 'loc') else None
            })
        
    def _get_function_name(self, node: esprima.nodes.Node) -> str:
        """获取函数名"""
        if node.type == 'Identifier':
            return node.name
        elif node.type == 'MemberExpression':
            obj = self._get_function_name(node.object)
            prop = node.property.name if hasattr(node.property, 'name') else str(node.property)
            return f"{obj}.{prop}"
        return "unknown"
        
    def _is_dangerous_function(self, func_name: str) -> bool:
        """检查是否为危险函数"""
        dangerous_functions = {
            'eval', 'Function', 'setTimeout', 'setInterval',
            'document.write', 'innerHTML', 'execScript'
        }
        return func_name in dangerous_functions 