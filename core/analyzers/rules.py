SECURITY_RULES = {
    'php': {
        'dangerous_functions': [
            {
                'pattern': r'eval\s*\(',
                'description': '使用eval()函数可能导致代码注入',
                'severity': 'high',
                'category': 'code_injection',
                'cwe': 'CWE-95'
            },
            # ... 更多规则
        ],
        'sql_injection': [
            {
                'pattern': r'\$_(?:GET|POST|REQUEST)\s*\[.*?\].*?(?:SELECT|INSERT|UPDATE|DELETE)',
                'description': '直接使用用户输入构造SQL语句',
                'severity': 'high',
                'category': 'sql_injection',
                'cwe': 'CWE-89'
            }
        ],
        # ... 更多类型
    },
    'python': {
        'dangerous_functions': [
            {
                'pattern': r'subprocess\.(?:call|Popen|run)',
                'description': '使用subprocess可能导致命令注入',
                'severity': 'high',
                'category': 'command_injection',
                'cwe': 'CWE-78'
            }
        ],
        # ... 更多规则
    }
} 