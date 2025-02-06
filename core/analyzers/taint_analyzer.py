import re

class TaintAnalyzer:
    def __init__(self):
        self.sources = set([
            'GET', 'POST', 'REQUEST', 'FILES', 'COOKIE',
            'file_get_contents', 'fgets', 'fread',
            'stdin', '$_SERVER', '$_ENV', 'getenv',
            'mysqli_query', 'mysql_query', 'PDO->query',
            'curl_exec', 'file', 'readfile', 'unserialize'
        ])
        self.sinks = set([
            'eval', 'exec', 'system', 'shell_exec',
            'passthru', 'popen', 'proc_open',
            'include', 'include_once', 'require', 'require_once',
            'mysqli_query', 'mysql_query', 'PDO->query',
            'echo', 'print', 'printf',
            'header',
            'file_put_contents', 'fwrite',
            'unserialize',
            'mail'
        ])
        self.sanitizers = set([
            'htmlspecialchars', 'htmlentities', 'strip_tags',
            'addslashes', 'escapeshellarg', 'escapeshellcmd'
        ])
        self.vulnerability_types = {
            'rce': ['eval', 'exec', 'system', 'shell_exec'],
            'sqli': ['mysqli_query', 'mysql_query', 'PDO->query'],
            'xss': ['echo', 'print', 'printf'],
            'file_inclusion': ['include', 'include_once', 'require'],
            'file_operation': ['file_put_contents', 'fwrite'],
            'deserialization': ['unserialize'],
            'header_injection': ['header', 'mail']
        }
        
        # 添加变量追踪映射
        self.variable_mapping = {}
        
        # 添加函数调用栈
        self.call_stack = []
        
        # 添加更多的漏洞模式
        self.vulnerability_patterns = {
            'sql_injection': {
                'risk_functions': ['query', 'execute'],
                'safe_patterns': [r'\?|:[a-zA-Z_][a-zA-Z0-9_]*'],  # 参数化查询模式
                'risk_patterns': [r".*\+.*'.*|.*'.*\+.*"]  # 字符串拼接模式
            },
            'xss': {
                'risk_functions': ['echo', 'print'],
                'safe_patterns': [r'htmlspecialchars\(.*\)|htmlentities\(.*\)'],
                'risk_patterns': [r'<.*>|javascript:']
            },
            'path_traversal': {
                'risk_functions': ['file_get_contents', 'fopen'],
                'risk_patterns': [r'\.\.\/|\.\.\\']
            }
        }
        
        # 添加更细粒度的漏洞检测规则
        self.detection_rules = {
            'java': {
                'sql_injection': {
                    'patterns': [
                        r'.*Statement\.executeQuery\(.*\+.*\)',
                        r'.*Statement\.execute\(.*\+.*\)',
                        r'.*PreparedStatement.*\+.*\)'
                    ],
                    'safe_patterns': [
                        r'PreparedStatement.*\?.*\)',
                        r'.*createQuery\(.*:.*\)'
                    ]
                },
                'command_injection': {
                    'patterns': [
                        r'Runtime\.exec\(.*\+.*\)',
                        r'ProcessBuilder.*\+.*\)',
                    ],
                    'safe_patterns': [
                        r'Runtime\.exec\(new String\[\].*\)'
                    ]
                },
                'xxe': {
                    'patterns': [
                        r'DocumentBuilder.*parse\(',
                        r'SAXParser.*parse\(',
                        r'XMLReader.*parse\('
                    ],
                    'safe_patterns': [
                        r'setFeature\(.*XMLConstants\.FEATURE_SECURE_PROCESSING.*true\)'
                    ]
                }
            }
        }
        
        # 添加框架特定的漏洞模式
        self.framework_patterns = {
            'spring': {
                'unsafe_redirects': [
                    r'redirect:.*\+',
                    r'sendRedirect\(.*\+.*\)'
                ],
                'csrf_vulnerable': [
                    r'@CrossOrigin\(.*allowCredentials\s*=\s*true.*\)',
                    r'@RequestMapping.*method\s*=\s*RequestMethod\.POST.*(?!@CrossOrigin)'
                ]
            },
            'hibernate': {
                'hql_injection': [
                    r'createQuery\(.*\+.*\)',
                    r'createSQLQuery\(.*\+.*\)'
                ]
            }
        }
        
        # 添加 Python 相关的检测规则
        self.detection_rules['python'] = {
            'command_injection': {
                'patterns': [
                    r'os\.system\(.*\+.*\)',
                    r'subprocess\.call\(.*\+.*\)',
                    r'subprocess\.Popen\(.*\+.*\)',
                    r'eval\(.*\+.*\)',
                    r'exec\(.*\+.*\)'
                ],
                'safe_patterns': [
                    r'subprocess\.run\([^,]+,\s*shell\s*=\s*False\)',
                    r'shlex\.quote\(.*\)'
                ]
            },
            'sql_injection': {
                'patterns': [
                    r'execute\(.*\+.*\)',
                    r'executemany\(.*\+.*\)',
                    r'raw\(.*\+.*\)',
                    r'\.format\(.*\)'
                ],
                'safe_patterns': [
                    r'execute\([^,]+,\s*\(.*\)\)',
                    r'execute\([^,]+,\s*\[.*\]\)'
                ]
            },
            'path_traversal': {
                'patterns': [
                    r'open\(.*\+.*\)',
                    r'os\.path\.join\(.*\+.*\)',
                    r'__import__\(.*\+.*\)'
                ],
                'safe_patterns': [
                    r'os\.path\.abspath\(.*\)',
                    r'os\.path\.realpath\(.*\)'
                ]
            },
            'deserialization': {
                'patterns': [
                    r'pickle\.loads\(',
                    r'yaml\.load\(',
                    r'marshal\.loads\('
                ],
                'safe_patterns': [
                    r'yaml\.safe_load\(',
                    r'json\.loads\('
                ]
            }
        }

        # 添加 JavaScript 相关的检测规则
        self.detection_rules['javascript'] = {
            'xss': {
                'patterns': [
                    r'innerHTML\s*=',
                    r'outerHTML\s*=',
                    r'document\.write\(',
                    r'eval\(',
                    r'\$\(.*\)\.html\('
                ],
                'safe_patterns': [
                    r'textContent\s*=',
                    r'innerText\s*=',
                    r'createElement\('
                ]
            },
            'dom_xss': {
                'patterns': [
                    r'location\s*=',
                    r'location\.href\s*=',
                    r'location\.search',
                    r'location\.hash'
                ],
                'safe_patterns': [
                    r'encodeURIComponent\(',
                    r'encodeURI\('
                ]
            },
            'prototype_pollution': {
                'patterns': [
                    r'Object\.assign\(',
                    r'Object\.prototype',
                    r'\.__proto__',
                    r'\.constructor\.prototype'
                ]
            },
            'insecure_randomness': {
                'patterns': [
                    r'Math\.random\(',
                ],
                'safe_patterns': [
                    r'crypto\.getRandomValues\(',
                    r'window\.crypto\.subtle'
                ]
            }
        }

        # 添加框架特定的检测规则
        self.framework_patterns['django'] = {
            'csrf_vulnerable': [
                r'@csrf_exempt',
                r'CSRF_COOKIE_SECURE\s*=\s*False'
            ],
            'sql_injection_risk': [
                r'raw\(',
                r'extra\(',
                r'RawSQL\('
            ]
        }

        self.framework_patterns['express'] = {
            'nosql_injection': [
                r'findOne\(.*\+.*\)',
                r'find\(.*\+.*\)',
                r'update\(.*\+.*\)'
            ],
            'security_misconfiguration': [
                r'app\.disable\(.*trust\s*proxy.*\)',
                r'app\.use\(bodyParser\.raw\(\)\)'
            ]
        }
    
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
        """增强的污点追踪"""
        if not node:
            return None
            
        vulnerabilities = []
        visited = set()
        
        def track_recursive(current_node, taint_chain=None, context=None):
            if not current_node or id(current_node) in visited:
                return
                
            visited.add(id(current_node))
            taint_chain = taint_chain or []
            context = context or {}
            
            # 记录变量赋值
            if self._is_assignment(current_node):
                self._track_variable_assignment(current_node)
            
            # 函数调用分析
            if self._is_function_call(current_node):
                self._analyze_function_call(current_node, context)
            
            # 条件语句分析
            if self._is_condition(current_node):
                self._analyze_condition_branch(current_node, context)
            
            # 检查是否经过安全的过滤
            if self._is_sanitized(current_node, context):
                context['sanitized'] = True
                return
            
            # 检查漏洞模式
            vuln = self._check_vulnerability_patterns(current_node, context)
            if vuln:
                vulnerabilities.append(vuln)
            
            # 递归分析
            for child in self._get_node_children(current_node):
                track_recursive(child, taint_chain + [current_node], context.copy())
        
        track_recursive(node)
        return vulnerabilities

    def _calculate_severity(self, vuln_type):
        """计算漏洞严重程度"""
        severity_map = {
            'rce': 'critical',
            'sqli': 'high',
            'xss': 'medium',
            'file_inclusion': 'high',
            'file_operation': 'medium',
            'deserialization': 'high',
            'header_injection': 'medium'
        }
        return severity_map.get(vuln_type, 'low')

    def _get_vulnerability_type(self, node):
        """确定漏洞类型"""
        if hasattr(node, 'name'):
            node_name = str(node.name)
            for vuln_type, sinks in self.vulnerability_types.items():
                if node_name in sinks:
                    return vuln_type
        return 'unknown'

    def _extract_context(self, node):
        """提取漏洞上下文"""
        context = {
            'code_snippet': self._get_code_snippet(node),
            'variables': self._get_related_variables(node),
            'function_scope': self._get_function_scope(node)
        }
        return context
        
    def _is_sink(self, node):
        """检查节点是否为危险函数"""
        if hasattr(node, 'name'):
            return str(node.name) in self.sinks
        return False

    def _analyze_function_call(self, node, context):
        """分析函数调用的安全性"""
        if not hasattr(node, 'name'):
            return
            
        func_name = str(node.name)
        
        # 检查是否是高风险函数
        for vuln_type, patterns in self.vulnerability_patterns.items():
            if func_name in patterns['risk_functions']:
                # 分析函数参数
                args = self._get_function_args(node)
                for arg in args:
                    if self._is_tainted(arg, context):
                        # 检查是否使用了安全的编码/过滤方式
                        if not self._has_safe_encoding(arg, patterns['safe_patterns']):
                            context['risks'].append({
                                'type': vuln_type,
                                'function': func_name,
                                'argument': str(arg)
                            })

    def _track_variable_assignment(self, node):
        """追踪变量赋值"""
        if hasattr(node, 'target') and hasattr(node, 'value'):
            var_name = str(node.target)
            self.variable_mapping[var_name] = {
                'value': str(node.value),
                'tainted': self._is_tainted(node.value),
                'sanitized': self._is_sanitized(node.value),
                'location': self._get_node_location(node)
            }

    def _analyze_condition_branch(self, node, context):
        """分析条件分支中的安全检查"""
        if hasattr(node, 'test'):
            # 检查是否包含安全验证
            if self._has_security_check(node.test):
                context['security_checked'] = True
            
            # 检查是否有风险的条件判断
            if self._has_risky_condition(node.test):
                context['risks'].append({
                    'type': 'unsafe_condition',
                    'condition': str(node.test),
                    'location': self._get_node_location(node)
                })

    def _has_security_check(self, node):
        """检查是否包含安全验证"""
        security_patterns = [
            r'validate|verify|check|auth|permission',
            r'is[A-Z]|has[A-Z]',
            r'sanitize|escape|encode'
        ]
        node_str = str(node)
        return any(re.search(pattern, node_str, re.I) for pattern in security_patterns)

    def _get_data_flow_path(self, node):
        """获取数据流路径"""
        path = []
        current = node
        while current and hasattr(current, 'parent'):
            path.append({
                'type': type(current).__name__,
                'value': str(current),
                'location': self._get_node_location(current)
            })
            current = current.parent
        return path[::-1]

    def _analyze_framework_specific(self, node, context):
        """分析框架特定的安全问题"""
        framework = self._detect_framework(context)
        if framework and framework in self.framework_patterns:
            patterns = self.framework_patterns[framework]
            for vuln_type, rules in patterns.items():
                if self._match_patterns(str(node), rules):
                    return {
                        'type': vuln_type,
                        'framework': framework,
                        'location': self._get_node_location(node),
                        'severity': 'high',
                        'description': f'发现{framework}框架相关的{vuln_type}漏洞'
                    }
        return None

    def _analyze_data_validation(self, node):
        """分析数据验证逻辑"""
        validation_info = {
            'has_validation': False,
            'validation_type': None,
            'validation_coverage': 0.0
        }
        
        # 检查是否使用了验证注解
        if self._has_validation_annotations(node):
            validation_info['has_validation'] = True
            validation_info['validation_type'] = 'annotation'
            
        # 检查是否有手动验证代码
        elif self._has_manual_validation(node):
            validation_info['has_validation'] = True
            validation_info['validation_type'] = 'manual'
            
        # 计算验证覆盖率
        validation_info['validation_coverage'] = self._calculate_validation_coverage(node)
        
        return validation_info

    def _analyze_authentication(self, node, context):
        """分析认证相关的安全问题"""
        auth_issues = []
        
        # 检查认证绕过
        if self._check_auth_bypass(node):
            auth_issues.append({
                'type': 'auth_bypass',
                'severity': 'critical',
                'location': self._get_node_location(node)
            })
            
        # 检查权限检查
        if not self._has_permission_check(node):
            auth_issues.append({
                'type': 'missing_permission_check',
                'severity': 'high',
                'location': self._get_node_location(node)
            })
            
        return auth_issues

    def _analyze_secure_configuration(self, node):
        """分析安全配置"""
        config_issues = []
        
        # 检查安全标头配置
        if not self._has_security_headers(node):
            config_issues.append({
                'type': 'missing_security_headers',
                'severity': 'medium'
            })
            
        # 检查安全cookie配置
        if not self._has_secure_cookie_config(node):
            config_issues.append({
                'type': 'insecure_cookie_config',
                'severity': 'medium'
            })
            
        return config_issues

    def _analyze_language_specific(self, node, language):
        """基于语言特性的分析"""
        if language not in self.detection_rules:
            return None
            
        rules = self.detection_rules[language]
        node_str = str(node)
        
        for vuln_type, patterns in rules.items():
            # 检查危险模式
            if 'patterns' in patterns:
                for pattern in patterns['patterns']:
                    if re.search(pattern, node_str):
                        # 检查是否有安全模式
                        if 'safe_patterns' in patterns:
                            if any(re.search(safe_pattern, node_str) 
                                  for safe_pattern in patterns['safe_patterns']):
                                continue
                                
                        return {
                            'type': vuln_type,
                            'language': language,
                            'location': self._get_node_location(node),
                            'code': node_str,
                            'severity': self._calculate_severity(vuln_type),
                            'description': f'发现{language}代码中的{vuln_type}漏洞'
                        }
        return None

    def _check_js_specific_issues(self, node):
        """检查JavaScript特有的安全问题"""
        issues = []
        
        # 检查不安全的第三方脚本引用
        if self._is_script_tag(node):
            if not self._has_integrity_check(node):
                issues.append({
                    'type': 'insecure_script_include',
                    'severity': 'medium',
                    'location': self._get_node_location(node),
                    'recommendation': '添加 SRI (Subresource Integrity) 校验'
                })
                
        # 检查敏感信息泄露
        if self._contains_sensitive_data(node):
            issues.append({
                'type': 'sensitive_data_exposure',
                'severity': 'high',
                'location': self._get_node_location(node),
                'recommendation': '避免在前端代码中硬编码敏感信息'
            })
            
        return issues

    def _check_python_specific_issues(self, node):
        """检查Python特有的安全问题"""
        issues = []
        
        # 检查不安全的模块导入
        if self._is_import(node):
            if self._is_dangerous_import(node):
                issues.append({
                    'type': 'dangerous_import',
                    'severity': 'medium',
                    'location': self._get_node_location(node),
                    'recommendation': '谨慎使用潜在危险的模块'
                })
                
        # 检查调试配置
        if self._is_debug_config(node):
            issues.append({
                'type': 'debug_enabled',
                'severity': 'medium',
                'location': self._get_node_location(node),
                'recommendation': '在生产环境中禁用调试模式'
            })
            
        return issues 