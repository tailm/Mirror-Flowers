from typing import Any, Optional, List, Dict
import logging
from pathlib import Path
import ast
import re
from phply import phplex, phpparse
import esprima
import os

logger = logging.getLogger(__name__)

class CodeParser:
    def __init__(self):
        # 添加更多的检查规则
        self.php_dangerous_patterns = {
            'dangerous_functions': [
                'eval', 'exec', 'system', 'shell_exec', 'passthru',
                'popen', 'proc_open', 'pcntl_exec', '`', 'assert'
            ],
            'sql_functions': [
                'mysql_query', 'mysqli_query', 'pg_query',
                'sqlite_query', 'db_query'
            ],
            'file_operations': [
                'fopen', 'file_get_contents', 'file_put_contents',
                'unlink', 'rmdir', 'mkdir', 'rename', 'copy'
            ],
            'weak_crypto': [
                'md5(', 'sha1(', 'mcrypt_', 'base64_encode('
            ],
            'insecure_configs': [
                'display_errors = On',
                'allow_url_fopen = On',
                'allow_url_include = On'
            ],
            'xss_vulnerable': [
                'echo $_', 'print $_', 'printf $_',
                'echo htmlspecialchars($_', 'print htmlspecialchars($_'
            ]
        }
        
        self.js_dangerous_patterns = {
            'dangerous_functions': [
                'eval(', 'Function(', 'setTimeout(', 'setInterval(',
                'execScript(', 'document.write('
            ],
            'xss_functions': [
                'innerHTML', 'outerHTML', 'insertAdjacentHTML',
                'document.write', 'document.writeln'
            ],
            'weak_crypto': [
                'Math.random()', 'crypto.getRandomValues('
            ],
            'sensitive_data': [
                'localStorage.setItem(', 'sessionStorage.setItem('
            ]
        }
        
    def parse(self, content: str, file_path: str) -> Optional[Dict]:
        """根据文件类型选择合适的解析器"""
        try:
            if not isinstance(file_path, (str, Path)):
                logger.error(f"无效的文件路径类型: {type(file_path)}")
                return None
            
            file_path = str(file_path)
            ext = os.path.splitext(file_path)[1].lower()
            if not ext:
                return None
                
            # 根据扩展名选择解析器
            if ext == '.php' or ext == '.blade.php':
                ast_result = self.parse_php(content)
                if ast_result:
                    return {
                        'type': 'php',
                        'ast': ast_result,
                        'content': content,
                        'file_path': file_path,
                        'suffix': ext
                    }
            elif ext == '.py':
                ast_result = self.parse_python(content)
                if ast_result:
                    return {
                        'type': 'python',
                        'ast': ast_result,
                        'content': content,
                        'file_path': file_path,
                        'suffix': ext
                    }
            elif ext in ['.js', '.ts', '.tsx']:
                ast_result = self.parse_typescript(content)
                if ast_result:
                    return {
                        'type': 'javascript',
                        'ast': ast_result,
                        'content': content,
                        'file_path': file_path,
                        'suffix': ext
                    }
            
            # 确保所有必要字段都有默认值
            result = self._create_empty_result()
            result.update({
                'content': content,
                'file_path': file_path,
                'suffix': ext
            })
            
            return result
            
        except Exception as e:
            logger.error(f"解析失败: {str(e)}")
            return None
            
    def _get_file_extension(self, file_path: str) -> Optional[str]:
        """获取文件扩展名，支持复合扩展名"""
        try:
            # 处理特殊情况：.blade.php
            if file_path.endswith('.blade.php'):
                return '.blade.php'
            return os.path.splitext(file_path)[1].lower()
        except Exception as e:
            logger.error(f"获取文件扩展名失败: {str(e)}")
            return None
            
    def parse_python(self, content: str) -> Optional[ast.AST]:
        """解析Python代码"""
        try:
            return ast.parse(content)
        except Exception as e:
            logger.error(f"Python解析失败: {str(e)}")
            return None
            
    def parse_php(self, content: str) -> Optional[Any]:
        """解析PHP代码"""
        try:
            # 预处理 PHP 代码
            content = self._preprocess_php(content)
            if not content:
                return None
            
            # 创建新的词法分析器
            lexer = phplex.lexer.clone()
            
            # 使用 phply 的解析器
            try:
                from phply.phpparse import make_parser
                parser = make_parser()
                ast = parser.parse(content, lexer=lexer)
                
                if not ast:
                    logger.warning("PHP解析器返回空AST，使用备用解析方法")
                    return None
                    
                # 进行深度安全分析
                security_analysis = self._analyze_php_security(content, ast)
                
                # 返回完整的结构
                result = self._create_empty_result()
                result.update({
                    'ast': ast,
                    'type': 'php',
                    'content': content,
                    'suffix': '.php',
                    'security_issues': security_analysis['issues'],
                    'recommendations': security_analysis['recommendations'],  # 添加建议
                    'dependencies': self._extract_php_dependencies(content),
                    'framework': self._detect_php_framework(content)
                })
                return result
                
            except (ImportError, AttributeError, SyntaxError) as e:
                logger.warning(f"PHP解析器错误: {str(e)}，使用备用解析方法")
                return None
            
        except Exception as e:
            logger.error(f"PHP解析失败: {str(e)}")
            return None
            
    def _analyze_php_security(self, content: str, ast: Any) -> List[Dict]:
        """分析PHP代码的安全问题"""
        issues = []
        recommendations = []  # 添加建议列表
        try:
            # 1. 检查危险模式
            for category, patterns in self.php_dangerous_patterns.items():
                for pattern in patterns:
                    matches = re.finditer(pattern, content)
                    for match in matches:
                        line_number = content.count('\n', 0, match.start()) + 1
                        issue = {
                            'type': category,
                            'line': line_number,
                            'description': f'发现{category}: {pattern}',
                            'severity': 'high' if category in ['dangerous_functions', 'sql_functions'] else 'medium',
                            'code_context': self._get_line_context(content, line_number)
                        }
                        issues.append(issue)
                        
                        # 根据问题类型添加相应的建议
                        if category == 'dangerous_functions':
                            recommendations.append({
                                'title': '危险函数使用建议',
                                'description': f'建议替换危险函数 {pattern}，使用更安全的替代方案',
                                'solution': self._get_security_recommendations(category, pattern),
                                'severity': 'high'
                            })
                        elif category == 'sql_functions':
                            recommendations.append({
                                'title': 'SQL注入风险建议',
                                'description': '使用参数化查询来防止SQL注入',
                                'solution': self._get_security_recommendations(category, pattern),
                                'severity': 'high'
                            })
                        # ... 其他类型的建议
            
            return {
                'issues': issues,
                'recommendations': recommendations  # 返回建议列表
            }
            
        except Exception as e:
            logger.error(f"安全分析失败: {str(e)}")
            return {'issues': [], 'recommendations': []}
            
    def _get_line_context(self, content: str, line_number: int, context_lines: int = 3) -> Dict:
        """获取代码行的上下文"""
        try:
            lines = content.splitlines()
            start = max(0, line_number - context_lines - 1)
            end = min(len(lines), line_number + context_lines)
            
            return {
                'before': lines[start:line_number-1],
                'line': lines[line_number-1],
                'after': lines[line_number:end]
            }
        except Exception:
            return {'before': [], 'line': '', 'after': []}
            
    def _extract_php_dependencies(self, content: str) -> List[str]:
        """提取PHP代码的依赖关系"""
        dependencies = []
        try:
            # 检查 use 语句
            use_matches = re.finditer(r'use\s+([\w\\]+)(?:\s+as\s+\w+)?;', content)
            for match in use_matches:
                dependencies.append(match.group(1))
                
            # 检查 require/include 语句
            require_matches = re.finditer(r'(?:require|include)(?:_once)?\s*[\'"]([^\'"]+)[\'"]', content)
            for match in require_matches:
                dependencies.append(match.group(1))
                
            return list(set(dependencies))
            
        except Exception as e:
            logger.error(f"提取依赖关系失败: {str(e)}")
            return []
            
    def _detect_php_framework(self, content: str) -> str:
        """检测PHP框架类型"""
        try:
            framework_patterns = {
                'laravel': [
                    r'use\s+Illuminate\\',
                    r'extends\s+Controller',
                    r'Laravel\\',
                ],
                'thinkphp': [
                    r'use\s+think\\',
                    r'extends\s+Controller',
                    r'namespace\s+app\\',
                ],
                'symfony': [
                    r'use\s+Symfony\\',
                    r'extends\s+AbstractController',
                    r'Bundle\\',
                ],
                'yii': [
                    r'use\s+yii\\',
                    r'extends\s+Controller',
                    r'Yii::',
                ]
            }
            
            for framework, patterns in framework_patterns.items():
                if any(re.search(pattern, content) for pattern in patterns):
                    return framework
                    
            return 'unknown'
            
        except Exception as e:
            logger.error(f"检测框架失败: {str(e)}")
            return 'unknown'
            
    def _create_empty_ast(self) -> Dict:
        """创建空的 AST 结构 - 已废弃，使用 _create_empty_result 替代"""
        return self._create_empty_result()
            
    def _preprocess_php(self, content: str) -> str:
        """预处理 PHP 代码"""
        try:
            if not content:
                return ''
            
            # 移除 BOM 标记
            content = content.replace('\ufeff', '')
            
            # 移除 PHP 标签
            content = re.sub(r'<\?(?:php)?\s+|\?>', '', content)
            
            # 处理命名空间
            content = re.sub(r'namespace\s+[\w\\]+\s*;', '', content)
            
            # 处理 use 语句
            content = re.sub(r'use\s+[\w\\]+(?:\s+as\s+\w+)?\s*;', '', content)
            
            # 移除注释
            content = re.sub(r'//.*$|/\*.*?\*/', '', content, flags=re.MULTILINE|re.DOTALL)
            
            # 移除空行
            content = '\n'.join(line for line in content.splitlines() if line.strip())
            
            return content
            
        except Exception as e:
            logger.error(f"PHP代码预处理失败: {str(e)}")
            return ''
            
    def parse_typescript(self, content: str) -> Optional[Any]:
        """解析TypeScript/JavaScript代码"""
        try:
            return esprima.parseScript(content, {'loc': True, 'range': True})
        except Exception as e:
            logger.error(f"TypeScript/JavaScript解析失败: {str(e)}")
            return None 

    def _create_empty_result(self) -> Dict:
        """创建空的结果结构"""
        return {
            'type': 'unknown',
            'ast': None,
            'content': '',
            'file_path': '',
            'suffix': '',
            'line': 0,
            'body': [],
            'loc': {'start': {'line': 1}},
            'start_line': 0,
            'end_line': 0,
            'start_column': 0,
            'end_column': 0
        }

    def _get_security_recommendations(self, category: str, pattern: str) -> str:
        """获取安全建议"""
        recommendations = {
            'dangerous_functions': {
                'eval': '使用更安全的方式如配置文件或数据库来存储和处理数据',
                'exec': '使用PHP内置函数或安全的库来执行系统命令',
                'system': '使用escapeshellcmd()和escapeshellarg()函数转义命令参数',
                'shell_exec': '使用proc_open()函数并严格控制命令参数'
            },
            'sql_functions': {
                'mysql_query': '使用PDO或mysqli预处理语句',
                'mysqli_query': '使用预处理语句和参数绑定',
                'pg_query': '使用pg_prepare()和pg_execute()'
            },
            'file_operations': {
                'fopen': '验证文件路径，使用realpath()函数',
                'file_get_contents': '检查URL或文件路径的合法性',
                'file_put_contents': '使用临时文件和原子操作'
            },
            'weak_crypto': {
                'md5': '使用password_hash()函数进行密码哈希',
                'sha1': '使用更强的哈希算法如SHA-256或SHA-3',
                'base64_encode': '不要用于加密，只用于编码'
            }
        }
        
        category_recommendations = recommendations.get(category, {})
        return category_recommendations.get(pattern, '遵循安全编码规范，进行输入验证和转义')

class PHPParser:
    def parse_file(self, file_path):
        """解析PHP文件并返回上下文"""
        try:
            # 基础验证
            if not file_path:
                logger.error("文件路径为空")
                return self._create_default_context(file_path)
                
            file_path = str(file_path)
            if not os.path.exists(file_path):
                logger.error(f"文件不存在: {file_path}")
                return self._create_default_context(file_path)
                
            # 读取文件内容
            content = self._read_file_content(file_path)
            if content is None:
                return self._create_default_context(file_path)
                
            # 获取文件扩展名
            ext = self._get_file_extension(file_path)
            if not ext:
                return self._create_default_context(file_path)
                
            # 解析内容
            parser = CodeParser()
            parse_result = parser.parse(content, file_path)
            
            if parse_result is None:
                logger.error(f"解析内容失败: {file_path}")
                return self._create_default_context(file_path)
                
            # 构建上下文，确保使用正确的文件路径和扩展名
            context = self._create_context_from_result(parse_result, file_path)
            
            # 额外的验证，确保suffix字段存在且有效
            if not context.get('suffix'):
                context['suffix'] = ext
                
            return context
            
        except Exception as e:
            logger.error(f"解析文件时发生错误: {str(e)}")
            return self._create_default_context(file_path)
            
    def _create_default_context(self, file_path: Optional[str] = None) -> Dict:
        """创建默认的上下文结构"""
        ext = self._get_file_extension(file_path) if file_path else ''
        return {
            'line': 0,
            'suffix': ext or '.php',  # 确保有默认扩展名
            'content': '',
            'file_path': str(file_path) if file_path else '',
            'type': 'php',  # 明确指定类型
            'ast': None,
            'body': [],
            'loc': {'start': {'line': 1}},
            'start_line': 0,
            'end_line': 0,
            'start_column': 0,
            'end_column': 0
        }
        
    def _get_file_extension(self, file_path: Optional[str]) -> str:
        """获取文件扩展名"""
        try:
            if not file_path:
                return '.php'
                
            if file_path.endswith('.blade.php'):
                return '.blade.php'
                
            ext = os.path.splitext(file_path)[1].lower()
            return ext if ext else '.php'
            
        except Exception as e:
            logger.error(f"获取文件扩展名失败: {str(e)}")
            return '.php'
            
    def _read_file_content(self, file_path: str) -> Optional[str]:
        """读取文件内容"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return f.read()
        except UnicodeDecodeError:
            try:
                with open(file_path, 'r', encoding='gbk') as f:
                    return f.read()
            except Exception as e:
                logger.error(f"读取文件失败 {file_path}: {str(e)}")
                return None
                
    def _create_context_from_result(self, parse_result: Dict, file_path: str) -> Dict:
        """从解析结果创建上下文"""
        ext = self._get_file_extension(file_path)
        return {
            'line': parse_result.get('line', 0),
            'suffix': parse_result.get('suffix', ext),  # 使用文件实际扩展名作为后备
            'content': parse_result.get('content', ''),
            'file_path': parse_result.get('file_path', file_path),  # 使用实际文件路径
            'type': parse_result.get('type', 'php'),  # 默认为php类型
            'ast': parse_result.get('ast'),
            'body': parse_result.get('body', []),
            'loc': parse_result.get('loc', {'start': {'line': 1}}),
            'start_line': parse_result.get('start_line', 0),
            'end_line': parse_result.get('end_line', 0),
            'start_column': parse_result.get('start_column', 0),
            'end_column': parse_result.get('end_column', 0)
        }
        
    def _validate_context(self, context: Dict) -> bool:
        """验证上下文的完整性"""
        try:
            required_keys = ['line', 'suffix', 'content', 'file_path', 'type', 'ast']
            
            # 检查所有必需的键是否存在
            missing_keys = [k for k in required_keys if k not in context]
            if missing_keys:
                logger.error(f"上下文缺少必要的键: {missing_keys}")
                return False
                
            # 验证类型
            if not isinstance(context['line'], int):
                logger.error(f"line 必须是整数类型，当前类型: {type(context['line'])}")
                return False
                
            if not isinstance(context['suffix'], str):
                logger.error(f"suffix 必须是字符串类型，当前类型: {type(context['suffix'])}")
                return False
                
            if not isinstance(context['content'], str):
                logger.error(f"content 必须是字符串类型，当前类型: {type(context['content'])}")
                return False
                
            return True
            
        except Exception as e:
            logger.error(f"验证上下文时发生错误: {str(e)}")
            return False
            
    def check_security_context(self, context):
        """检查安全上下文"""
        try:
            # 如果上下文为空或不是字典类型，返回空列表
            if not context or not isinstance(context, dict):
                logger.error(f"无效的上下文: {type(context)}")
                return []
                
            # 验证必要字段
            required_keys = ['line', 'suffix', 'content', 'file_path', 'type', 'ast']
            if not all(key in context for key in required_keys):
                missing_keys = [k for k in required_keys if k not in context]
                logger.error(f"上下文缺少必要的键: {missing_keys}")
                return []
                
            # 验证字段类型并提供默认值
            context['line'] = int(context.get('line', 0))
            context['suffix'] = str(context.get('suffix', ''))
            context['content'] = str(context.get('content', ''))
            
            # 执行安全检查
            security_issues = []
            
            # 检查 AST
            if context.get('ast'):
                # 实现基于 AST 的安全检查逻辑
                pass
                
            # 检查原始内容
            if context.get('content'):
                # 实现基于内容的安全检查逻辑
                pass
                
            return security_issues
            
        except Exception as e:
            logger.error(f"检查安全上下文时发生错误: {str(e)}")
            return [] 