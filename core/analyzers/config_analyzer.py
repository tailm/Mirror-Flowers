class ConfigAnalyzer:
    def __init__(self):
        self.dangerous_configs = {
            'php': {
                'allow_url_fopen': 'On',
                'allow_url_include': 'On',
                'display_errors': 'On',
                'expose_php': 'On'
            },
            'java': {
                'debug': 'true',
                'trace': 'true',
                'security.basic.enabled': 'false'
            }
        }
        
        # 添加更多配置检查规则
        self.security_rules = {
            'authentication': {
                'required_settings': ['session.cookie_secure', 'session.cookie_httponly'],
                'forbidden_settings': ['session.use_only_cookies=0']
            },
            'file_upload': {
                'check_settings': ['upload_max_filesize', 'max_file_uploads'],
                'risk_values': ['unlimited', '-1']
            },
            'error_reporting': {
                'production_settings': {
                    'display_errors': 'Off',
                    'log_errors': 'On',
                    'error_reporting': 'E_ALL & ~E_DEPRECATED & ~E_STRICT'
                }
            }
        }
        
    def analyze(self, config_files):
        """增强的配置分析"""
        issues = []
        
        for file_path in config_files:
            config_type = self._detect_config_type(file_path)
            
            # 基本配置检查
            basic_issues = self._check_dangerous_settings(file_path, config_type)
            issues.extend(basic_issues)
            
            # 环境特定检查
            env_issues = self._check_environment_specific(file_path, config_type)
            issues.extend(env_issues)
            
            # 安全规则检查
            security_issues = self._check_security_rules(file_path, config_type)
            issues.extend(security_issues)
            
        return self._prioritize_issues(issues) 