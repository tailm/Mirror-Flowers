from typing import Dict, List, Set, Any
from pathlib import Path
import ast
import logging

logger = logging.getLogger(__name__)

class Variable:
    def __init__(self, name: str, value=None, tainted=False):
        self.name = name
        self.value = value
        self.tainted = tainted
        self.sources = set()  # 变量来源
        self.sinks = set()    # 变量去向
        self.line_no = None   # 定义行号
        self.references = []  # 引用位置

class DataFlowAnalyzer:
    def __init__(self):
        self.variables: Dict[str, Variable] = {}
        self.taint_sources = {
            'php': ['$_GET', '$_POST', '$_REQUEST', '$_COOKIE', '$_FILES'],
            'python': ['request.form', 'request.args', 'request.files'],
            'javascript': ['document.location', 'window.location', 'URL parameters']
        }
        self.sensitive_sinks = {
            'php': {
                'sql': ['mysql_query', 'mysqli_query', 'PDO::query'],
                'command': ['exec', 'system', 'shell_exec', 'passthru'],
                'file': ['file_get_contents', 'file_put_contents', 'fopen']
            },
            'python': {
                'sql': ['execute', 'executemany', 'raw'],
                'command': ['subprocess.run', 'os.system', 'os.popen'],
                'file': ['open', 'read', 'write']
            }
        }

    def analyze(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        """执行数据流分析"""
        issues = []
        try:
            # 1. 构建AST
            tree = self._parse_code(content, file_path)
            if not tree:
                return []

            # 2. 变量追踪
            self._track_variables(tree)

            # 3. 污点分析
            taint_issues = self._taint_analysis()
            issues.extend(taint_issues)

            # 4. 变量传播分析
            propagation_issues = self._analyze_propagation()
            issues.extend(propagation_issues)

            # 5. 上下文分析
            context_issues = self._analyze_context(tree)
            issues.extend(context_issues)

            return issues

        except Exception as e:
            logger.error(f"数据流分析失败 {file_path}: {str(e)}")
            return []

    def _track_variables(self, tree: ast.AST) -> None:
        """追踪变量定义和使用"""
        class VariableTracker(ast.NodeVisitor):
            def __init__(self, analyzer):
                self.analyzer = analyzer
                self.scope_stack = []

            def visit_Assign(self, node):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        var = Variable(target.id)
                        var.line_no = node.lineno
                        # 分析赋值来源
                        if isinstance(node.value, ast.Call):
                            var.sources.add(self._get_call_source(node.value))
                        self.analyzer.variables[target.id] = var
                self.generic_visit(node)

            def visit_Call(self, node):
                # 记录函数调用中的变量使用
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                    for arg in node.args:
                        if isinstance(arg, ast.Name) and arg.id in self.analyzer.variables:
                            self.analyzer.variables[arg.id].sinks.add(func_name)
                self.generic_visit(node)

            def _get_call_source(self, node):
                if isinstance(node.func, ast.Name):
                    return node.func.id
                elif isinstance(node.func, ast.Attribute):
                    return f"{self._get_call_source(node.func.value)}.{node.func.attr}"
                return "unknown"

        tracker = VariableTracker(self)
        tracker.visit(tree)

    def _taint_analysis(self) -> List[Dict[str, Any]]:
        """执行污点分析"""
        issues = []
        for var_name, var in self.variables.items():
            # 检查变量是否来自污点源
            if self._is_from_taint_source(var):
                var.tainted = True
                # 检查是否流向敏感接收器
                for sink in var.sinks:
                    if self._is_sensitive_sink(sink):
                        issues.append({
                            "type": "taint_flow",
                            "description": f"污点数据从 {list(var.sources)} 流向敏感接收器 {sink}",
                            "severity": "high",
                            "line": var.line_no,
                            "variable": var_name,
                            "source": list(var.sources),
                            "sink": sink
                        })
        return issues

    def _analyze_propagation(self) -> List[Dict[str, Any]]:
        """分析变量传播"""
        issues = []
        # 构建变量依赖图
        dependency_graph = self._build_dependency_graph()
        # 分析变量传播链
        for var_name in self.variables:
            propagation_chain = self._get_propagation_chain(var_name, dependency_graph)
            if len(propagation_chain) > 1:  # 存在传播链
                if any(self._is_from_taint_source(self.variables[v]) for v in propagation_chain):
                    issues.append({
                        "type": "variable_propagation",
                        "description": f"发现污点数据传播链: {' -> '.join(propagation_chain)}",
                        "severity": "medium",
                        "propagation_chain": propagation_chain
                    })
        return issues

    def _analyze_context(self, tree: ast.AST) -> List[Dict[str, Any]]:
        """分析代码上下文"""
        issues = []
        # 分析异常处理
        exception_issues = self._analyze_exception_handling(tree)
        issues.extend(exception_issues)
        # 分析条件判断
        condition_issues = self._analyze_conditions(tree)
        issues.extend(condition_issues)
        # 分析循环结构
        loop_issues = self._analyze_loops(tree)
        issues.extend(loop_issues)
        return issues

    def _is_from_taint_source(self, var: Variable) -> bool:
        """检查变量是否来自污点源"""
        return any(source in self.taint_sources.get(self.language, []) 
                  for source in var.sources)

    def _is_sensitive_sink(self, sink: str) -> bool:
        """检查是否为敏感接收器"""
        for category in self.sensitive_sinks.get(self.language, {}):
            if sink in self.sensitive_sinks[self.language][category]:
                return True
        return False

    def _build_dependency_graph(self) -> Dict[str, Set[str]]:
        """构建变量依赖图"""
        graph = {}
        for var_name, var in self.variables.items():
            graph[var_name] = set()
            for ref in var.references:
                if isinstance(ref, ast.Name) and ref.id in self.variables:
                    graph[var_name].add(ref.id)
        return graph

    def _get_propagation_chain(self, start: str, graph: Dict[str, Set[str]], 
                             visited: Set[str] = None) -> List[str]:
        """获取变量传播链"""
        if visited is None:
            visited = set()
        if start in visited:
            return []
        visited.add(start)
        chain = [start]
        for next_var in graph.get(start, set()):
            if next_var not in visited:
                sub_chain = self._get_propagation_chain(next_var, graph, visited)
                if sub_chain:
                    chain.extend(sub_chain)
        return chain 