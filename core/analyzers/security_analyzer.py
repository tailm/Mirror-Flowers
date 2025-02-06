class SecurityAnalyzer:
    def __init__(self):
        self.patterns = {
            'weak_crypto': [
                r'md5\(',
                r'sha1\(',
                r'crypt\(',
                r'des_encrypt\('
            ],
            'hardcoded_secrets': [
                r'password\s*=\s*[\'"][^\'"]+[\'"]',
                r'secret\s*=\s*[\'"][^\'"]+[\'"]',
                r'api_key\s*=\s*[\'"][^\'"]+[\'"]'
            ],
            'insecure_config': [
                r'display_errors\s*=\s*On',
                r'allow_url_include\s*=\s*On',
                r'register_globals\s*=\s*On'
            ],
            'csrf_vulnerability': [
                r'form.*method=[\'"]post[\'"].*(?!.*csrf)',
                r'ajax\.post\(.*(?!.*token)'
            ]
        }
        
    def analyze(self, code, file_type):
        """执行安全分析"""
        vulnerabilities = []
        
        # 根据文件类型选择不同的分析策略
        if file_type == 'php':
            vulnerabilities.extend(self._analyze_php(code))
        elif file_type == 'java':
            vulnerabilities.extend(self._analyze_java(code))
            
        return vulnerabilities 