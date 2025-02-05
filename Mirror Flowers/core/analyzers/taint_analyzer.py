class TaintAnalyzer:
    def __init__(self):
        self.sources = set([
            'GET', 'POST', 'REQUEST', 'FILES', 'COOKIE',
            'file_get_contents', 'fgets', 'fread'
        ])
        self.sinks = set([
            'eval', 'exec', 'system', 'shell_exec',
            'passthru', 'popen', 'proc_open'
        ])
        self.sanitizers = set([
            'htmlspecialchars', 'htmlentities', 'strip_tags',
            'addslashes', 'escapeshellarg', 'escapeshellcmd'
        ])
    
    def analyze(self, ast_tree):
        """
        执行污点分析
        """
        vulnerabilities = []
        
        # 遍历AST寻找污点传播路径
        for node in ast_tree.traverse():
            if self._is_source(node):
                taint = self._track_taint(node)
                if taint:
                    vulnerabilities.append(taint)
                    
        return vulnerabilities
    
    def _is_source(self, node):
        """检查节点是否为污点源"""
        # 实现基本的污点源检查
        if hasattr(node, 'name'):
            return str(node.name) in self.sources
        return False

    def _track_taint(self, node):
        """追踪污点传播"""
        if not node:
            return None
            
        # 基本的污点追踪实现
        if hasattr(node, 'children'):
            for child in node.children:
                if self._is_sink(child):
                    return {
                        'type': 'taint_flow',
                        'source': str(node),
                        'sink': str(child),
                        'severity': 'high'
                    }
        return None
        
    def _is_sink(self, node):
        """检查节点是否为危险函数"""
        if hasattr(node, 'name'):
            return str(node.name) in self.sinks
        return False 