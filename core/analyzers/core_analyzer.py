from typing import List, Dict, Any
from pathlib import Path
import logging
from .taint_analyzer import TaintAnalyzer
from .security_analyzer import SecurityAnalyzer
from .framework_analyzer import FrameworkAnalyzer
from ..database.vector_store import CodeVectorStore
import json
import asyncio
from typing import Optional
import os
import ast
import re
from backend.config import settings
from openai import AsyncOpenAI
from .parsers import CodeParser
from .visitors import PHPASTVisitor, TypeScriptASTVisitor

logger = logging.getLogger(__name__)

class CoreAnalyzer:
    def __init__(self):
        self.taint_analyzer = TaintAnalyzer()
        self.security_analyzer = SecurityAnalyzer() 
        self.framework_analyzer = FrameworkAnalyzer()
        self.vector_store = CodeVectorStore()
        self.parser = CodeParser()
        self.issues = []
        
    async def analyze_project(self, project_path: str) -> Dict[str, Any]:
        """分析整个项目
        
        1. 首先进行本地静态扫描
        2. 将代码导入向量数据库
        3. 对可疑代码进行AI验证
        """
        try:
            project_path = Path(project_path)
            
            # 1. 本地静态扫描
            suspicious_files = await self._static_scan(str(project_path))
            
            # 2. 导入向量数据库
            await self._import_to_vector_store(str(project_path))
            
            # 3. AI验证可疑代码
            results = await self._ai_verify_suspicious(suspicious_files)
            
            return {
                "status": "success",
                "message": "分析完成",
                "suspicious_files": suspicious_files,
                "ai_verification": results,
                "summary": {
                    "total_files": len(suspicious_files),
                    "total_issues": sum(len(file.get("issues", [])) for file in suspicious_files),
                    "risk_level": self._calculate_risk_level(suspicious_files)
                },
                "recommendations": self._generate_recommendations(suspicious_files, results)
            }
            
        except Exception as e:
            logger.error(f"Project analysis failed: {str(e)}")
            return {
                "status": "error",
                "message": str(e),
                "suspicious_files": [],
                "ai_verification": {},
                "summary": {
                    "total_files": 0,
                    "total_issues": 0,
                    "risk_level": "unknown"
                },
                "recommendations": []
            }

    def _parse_code(self, content: str, file_path: str) -> Any:
        """解析代码为AST"""
        try:
            if not isinstance(file_path, (str, Path)):
                logger.error(f"无效的文件路径类型: {type(file_path)}")
                return None
                
            # 使用 CodeParser 进行解析
            parser = CodeParser()
            result = parser.parse(content, file_path)
            
            # 确保返回有效的结果
            if not result or not isinstance(result, dict):
                logger.error(f"解析结果无效: {file_path}")
                return None
                
            # 确保必要的字段存在
            if 'ast' not in result:
                logger.error(f"解析结果缺少AST: {file_path}")
                return None
                
            return result['ast']  # 只返回AST部分
            
        except Exception as e:
            logger.error(f"解析代码失败 {file_path}: {str(e)}")
            return None
            
    def analyze_file(self, content: str, file_path: str) -> List[Dict]:
        """分析单个文件"""
        try:
            # 检查文件是否存在
            if not os.path.exists(file_path):
                logger.error(f"文件不存在: {file_path}")
                return []
                
            # 检查文件类型
            ext = os.path.splitext(file_path)[1].lower()
            if not ext:
                logger.error(f"无法确定文件类型: {file_path}")
                return []
                
            # 检查可疑代码
            issues = self._check_suspicious(content, file_path)
            
            # 如果是PHP文件，进行额外的安全检查
            if ext == '.php' or ext == '.blade.php':
                try:
                    parser = CodeParser()
                    ast = parser.parse(content, file_path)
                    if ast and isinstance(ast, dict) and 'ast' in ast:
                        security_context = self._check_security_context(ast['ast'], file_path)
                        if not security_context.get('has_validation', False):
                            issues.append({
                                'type': 'security',
                                'line': ast.get('line', 0),
                                'description': '缺少输入验证',
                                'severity': 'medium',
                                'file': file_path
                            })
                except Exception as e:
                    logger.error(f"检查安全上下文失败: {str(e)}")
                    
            return issues
            
        except Exception as e:
            logger.error(f"分析文件失败 {file_path}: {str(e)}")
            return []

    def _check_suspicious(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        """检查文件是否包含可疑代码"""
        try:
            # 获取文件扩展名
            file_path = str(file_path)  # 确保是字符串
            if file_path.endswith('.blade.php'):
                ext = '.blade.php'
            else:
                ext = os.path.splitext(file_path)[1].lower()
            
            # 根据文件类型进行检查
            if ext == '.php' or ext == '.blade.php':
                issues = self._simple_php_check(content)
            elif ext in ['.js', '.ts', '.tsx']:
                issues = self._simple_js_check(content)
            else:
                issues = self._simple_code_check(content)
                
            # 添加文件路径信息
            for issue in issues:
                issue['file'] = file_path
                
            return issues
            
        except Exception as e:
            logger.error(f"检查代码失败 {file_path}: {str(e)}")
            return []

    async def _static_scan(self, project_path: str) -> List[Dict[str, Any]]:
        """静态扫描项目文件"""
        suspicious_files = []
        try:
            project_path = str(project_path)
            valid_files = []
            
            # 扫描文件
            for root, _, files in os.walk(project_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    if file_path.endswith(('.php', '.blade.php', '.js', '.ts', '.tsx', '.py')):
                        valid_files.append(file_path)
                        logger.debug(f"添加有效文件: {file_path}")
                        
            logger.info(f"找到 {len(valid_files)} 个待分析文件")
            
            # 分析每个文件
            for file_path in valid_files:
                try:
                    # 读取文件内容
                    content = self._read_file_content(file_path)
                    if not content:
                        logger.warning(f"无法读取文件内容: {file_path}")
                        continue
                        
                    logger.debug(f"开始分析文件: {file_path}")
                    
                    # 检查可疑代码
                    issues = self._check_suspicious(content, file_path)
                    if issues:
                        suspicious_files.append({
                            "file_path": file_path,
                            "issues": issues,
                            "language": self._detect_language(file_path),
                            "context": self._get_context_info(file_path)
                        })
                        logger.debug(f"发现 {len(issues)} 个问题: {file_path}")
                        
                except Exception as e:
                    logger.error(f"分析文件失败 {file_path}: {str(e)}")
                    continue
                    
            logger.info(f"扫描完成，发现 {len(suspicious_files)} 个可疑文件")
            return suspicious_files
            
        except Exception as e:
            logger.error(f"静态扫描失败: {str(e)}")
            return []

    def _filter_false_positives(self, issues: List[Dict], content: str, 
                              file_path: str) -> List[Dict]:
        """过滤误报"""
        filtered = []
        for issue in issues:
            # 1. 检查是否在安全上下文中
            if self._is_in_safe_context(issue, content):
                continue
            
            # 2. 检查是否有足够的验证
            if self._has_sufficient_validation(issue, content):
                continue
            
            # 3. 检查是否在测试代码中
            if self._is_test_code(file_path):
                continue
            
            filtered.append(issue)
        return filtered

    def _is_in_safe_context(self, issue: Dict, content: str) -> bool:
        """检查是否在安全上下文中"""
        try:
            # 获取问题所在行的上下文
            lines = content.splitlines()
            issue_line = lines[issue.get('line', 1) - 1]
            
            # 检查是否有安全处理
            safe_patterns = [
                r'escape', r'htmlspecialchars', r'sanitize',
                r'validate', r'filter', r'prepared'
            ]
            
            # 向上查找5行
            start = max(0, issue.get('line', 1) - 5)
            context_lines = lines[start:issue.get('line', 1)]
            
            return any(any(pattern in line for pattern in safe_patterns)
                      for line in context_lines)
        except Exception as e:
            logger.error(f"检查安全上下文失败: {str(e)}")
            return False

    async def _scan_single_file(self, file_path: Path) -> Optional[Dict[str, Any]]:
        """扫描单个文件"""
        try:
            # 尝试不同的编码读取文件
            content = None
            encodings = ['utf-8', 'gbk', 'latin1']
            for encoding in encodings:
                try:
                    with open(file_path, "r", encoding=encoding) as f:
                        content = f.read()
                    break
                except UnicodeDecodeError:
                    continue
                
            if content is None:
                logger.warning(f"无法读取文件 {file_path}，跳过")
                return None
            
            # 并发执行各类分析
            taint_task = asyncio.create_task(self.taint_analyzer.analyze(content))
            security_task = asyncio.create_task(self.security_analyzer.analyze(content))
            framework_task = asyncio.create_task(
                self.framework_analyzer.analyze_framework(
                    content,
                    self._detect_framework(content)
                )
            )
            
            # 等待所有分析完成
            taint_issues, security_issues, framework_issues = await asyncio.gather(
                taint_task, security_task, framework_task
            )
            
            return {
                "file_path": str(file_path),  # 转换为字符串
                "issues": {
                    "taint": taint_issues,
                    "security": security_issues,
                    "framework": framework_issues
                },
                "language": self._detect_language(file_path)
            }
        except Exception as e:
            logger.error(f"Error scanning {file_path}: {str(e)}")
            return None

    async def _import_to_vector_store(self, project_path: str) -> None:
        """将源代码导入向量数据库"""
        try:
            code_snippets = []
            project_path = Path(project_path)  # 转换为 Path 对象
            
            for file_path in project_path.rglob("*"):
                if not self._is_source_file(file_path):
                    continue
                    
                try:
                    # 尝试不同的编码读取文件
                    content = None
                    encodings = ['utf-8', 'gbk', 'latin1']
                    for encoding in encodings:
                        try:
                            with open(file_path, "r", encoding=encoding) as f:
                                content = f.read()
                            break
                        except UnicodeDecodeError:
                            continue
                            
                    if content is None:
                        logger.warning(f"无法读取文件 {file_path}，跳过")
                        continue
                        
                    code_snippets.append({
                        "code": content,
                        "file_path": str(file_path),  # 转换为字符串
                        "line_start": 1,
                        "line_end": len(content.splitlines()),
                        "metadata": {
                            "framework": self._detect_framework(content),
                            "language": self._detect_language(file_path)
                        }
                    })
                    
                except Exception as e:
                    logger.error(f"Error importing {file_path}: {str(e)}")
                    
            if code_snippets:
                await self.vector_store.add_code_to_store(code_snippets)
            
        except Exception as e:
            logger.error(f"导入向量数据库失败: {str(e)}")
            raise

    async def _ai_verify_suspicious(self, suspicious_files: List[Dict[str, Any]]) -> Dict[str, Any]:
        """AI验证可疑代码"""
        # 从配置文件读取API设置
        config_path = Path(__file__).parent.parent.parent / "config" / "api_config.json"
        if config_path.exists():
            with open(config_path, "r") as f:
                config = json.load(f)
                api_key = config.get("api_key")
                api_base = config.get("api_base")
                model = config.get("model")
        else:
            api_key = settings.OPENAI_API_KEY
            api_base = settings.OPENAI_API_BASE
            model = settings.OPENAI_MODEL

        if not api_key:
            raise ValueError("未配置API密钥")

        # 创建 OpenAI 客户端
        client = AsyncOpenAI(
            api_key=api_key,
            base_url=api_base
        )

        results = {}
        
        for file_info in suspicious_files:
            file_path = file_info["file_path"]
            
            try:
                # 获取文件内容
                content = self._get_file_content(file_path)
                if not content:
                    continue
                    
                # 构建分析提示
                prompt = f"""请对以下代码进行安全审计并以JSON格式返回分析结果：

文件路径: {file_path}
发现的问题: {json.dumps(file_info.get('issues', []), ensure_ascii=False)}

源代码:
{content}

请以以下JSON格式返回分析结果：
{{
    "vulnerability_confirmation": {{
        "dangerous_function": {{
            "is_false_positive": false,
            "evidence": "具体的漏洞证据"
        }}
    }},
    "impact_analysis": {{
        "dangerous_function": {{
            "severity": "high/medium/low",
            "exploit_conditions": "利用条件描述",
            "impact_scope": "影响范围描述"
        }}
    }},
    "remediation_suggestions": {{
        "dangerous_function": {{
            "code_level_fix": "具体的代码修复建议",
            "secure_coding_practices": "安全编码建议",
            "security_configuration_suggestions": "安全配置建议"
        }}
    }},
    "correlation_analysis": {{
        "dangerous_function": {{
            "association": "漏洞关联性分析",
            "exploit_combination": "组合利用分析",
            "overall_remediation_strategy": "整体修复策略"
        }}
    }}
}}"""

                # 调用AI API
                results[file_path] = {
                    "issues": file_info.get('issues', []),
                    "similar_code": [],
                    "ai_analysis": await self._call_ai_api(prompt)
                }
                
            except Exception as e:
                logger.error(f"AI分析失败 {file_path}: {str(e)}")
                continue
        
        return results

    def _is_source_file(self, file_path: Path) -> bool:
        """检查是否为源代码文件"""
        try:
            # 检查是否为文件
            if not file_path.is_file():
                return False
            
            # 获取文件扩展名（转换为小写）
            ext = file_path.suffix.lower()
            
            # 支持的文件类型
            supported_extensions = {
                # Web
                '.php', '.html', '.htm', '.js', '.jsx', '.ts', '.tsx', '.vue', '.css',
                # Python
                '.py', '.pyw', '.pyx',
                # Java
                '.java', '.jsp', '.jspx',
                # .NET
                '.cs', '.vb', '.aspx', '.ascx',
                # 其他
                '.go', '.rb', '.pl', '.sh', '.sql'
            }
            
            # 忽略的目录
            ignore_dirs = {'node_modules', 'venv', '.git', '.svn', '__pycache__', 
                          'vendor', 'dist', 'build', 'target'}
            
            # 检查是否在忽略目录中
            if any(part in ignore_dirs for part in file_path.parts):
                return False
            
            # 检查是否为隐藏文件
            if file_path.name.startswith('.'):
                return False
            
            # 检查扩展名
            return ext in supported_extensions
        
        except Exception as e:
            logger.error(f"检查文件类型失败 {file_path}: {str(e)}")
            return False

    def _detect_language(self, file_path: str) -> str:
        """检测文件语言类型"""
        try:
            # 确保file_path是字符串类型
            file_path = str(file_path)
            
            # 处理特殊情况
            if file_path.endswith('.blade.php'):
                return 'php'
                
            # 获取扩展名
            ext = os.path.splitext(file_path)[1].lower()
            
            # 语言映射
            language_map = {
                '.php': 'php',
                '.js': 'javascript',
                '.ts': 'typescript',
                '.tsx': 'typescript',
                '.py': 'python'
            }
            
            return language_map.get(ext, 'unknown')
            
        except Exception as e:
            logger.error(f"检测语言类型失败 {file_path}: {str(e)}")
            return 'unknown'

    def _detect_framework(self, content: str) -> str:
        """检测使用的框架"""
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
            'django': [
                r'from\s+django\.',
                r'models\.Model',
                r'@login_required',
            ],
            'flask': [
                r'from\s+flask\s+import',
                r'@app\.route',
                r'Flask\(',
            ],
            'express': [
                r'express\(\)',
                r'app\.get\(',
                r'app\.post\(',
            ],
            'spring': [
                r'@Controller',
                r'@RequestMapping',
                r'@Autowired',
            ]
        }
        
        detected_frameworks = []
        
        for framework, patterns in framework_patterns.items():
            if any(re.search(pattern, content) for pattern in patterns):
                detected_frameworks.append(framework)
            
        return detected_frameworks[0] if detected_frameworks else 'unknown'

    def _get_file_content(self, file_path: str) -> str:
        """获取文件内容"""
        try:
            # 确保file_path是字符串类型
            file_path = str(file_path)
            
            # 尝试不同的编码
            encodings = ['utf-8', 'gbk', 'latin1']
            for encoding in encodings:
                try:
                    with open(file_path, "r", encoding=encoding) as f:
                        return f.read()
                except UnicodeDecodeError:
                    continue
                
            logger.warning(f"无法读取文件 {file_path}")
            return ""
        
        except Exception as e:
            logger.error(f"获取文件内容失败 {file_path}: {str(e)}")
            return ""
            
    def _generate_analysis_prompt(self, issues: List[Dict], similar_code: List) -> str:
        """生成更详细的AI分析提示"""
        try:
            # 确保 issues 是可序列化的
            if isinstance(issues, str):
                try:
                    issues = json.loads(issues)
                except json.JSONDecodeError:
                    issues = []
            
            # 格式化 issues
            issues_str = json.dumps(issues, indent=2, ensure_ascii=False) if issues else "[]"
            
            # 格式化 similar_code
            similar_code_str = json.dumps(similar_code, indent=2, ensure_ascii=False) if similar_code else "[]"
            
            prompt = f"""请分析以下代码中的安全漏洞：

发现的问题：
{issues_str}

相似代码上下文：
{similar_code_str}

请提供以下分析：
1. 漏洞确认
   - 验证每个发现的漏洞是否为误报
   - 提供漏洞存在的具体证据

2. 影响分析
   - 评估每个漏洞的实际危害
   - 分析漏洞的利用条件
   - 评估漏洞的影响范围

3. 修复建议
   - 提供具体的代码级修复方案
   - 建议的安全编码实践
   - 相关的安全配置建议

4. 关联分析
   - 分析漏洞间的关联性
   - 评估组合利用的可能性
   - 建议的整体修复策略

请以JSON格式返回分析结果。
"""
            return prompt
            
        except Exception as e:
            logger.error(f"生成分析提示失败: {str(e)}")
            return ""
        
    async def _call_ai_api(self, prompt: str) -> Dict:
        """调用AI API进行代码分析"""
        try:
            # 从配置文件读取API设置
            config_path = Path(__file__).parent.parent.parent / "config" / "api_config.json"
            if config_path.exists():
                with open(config_path, "r") as f:
                    config = json.load(f)
                    api_key = config.get("api_key")
                    api_base = config.get("api_base")
                    model = config.get("model")
            else:
                # 如果配置文件不存在,使用环境变量或默认值
                api_key = settings.OPENAI_API_KEY
                api_base = settings.OPENAI_API_BASE
                model = settings.OPENAI_MODEL

            if not api_key:
                raise ValueError("未配置API密钥")

            # 创建 OpenAI 客户端
            client = AsyncOpenAI(
                api_key=api_key,
                base_url=api_base
            )
            
            # 调用 API
            response = await client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": "你是一个专业的代码安全审计专家。请分析代码中的安全问题并提供修复建议。"},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.2,
                max_tokens=2000
            )
            
            # 获取响应文本
            analysis_text = response.choices[0].message.content
            
            # 尝试从响应文本中提取JSON内容
            try:
                # 如果返回的是markdown代码块，提取其中的JSON内容
                if analysis_text.startswith('```') and analysis_text.endswith('```'):
                    # 移除markdown代码块标记
                    json_str = analysis_text.split('\n', 1)[1].rsplit('\n', 1)[0]
                    if json_str.startswith('json'):
                        json_str = json_str[4:].strip()
                    analysis_data = json.loads(json_str)
                else:
                    # 直接尝试解析JSON
                    analysis_data = json.loads(analysis_text)
                    
                # 构造前端期望的响应格式
                return {
                    "status": "success",
                    "analysis": {
                        # 将对象转换为格式化的JSON字符串
                        "raw_text": json.dumps(analysis_data, ensure_ascii=False, indent=2),
                        "summary": {
                            "risk_level": analysis_data.get("impact_analysis", {})
                                .get("dangerous_function", {})
                                .get("severity", "unknown"),
                            "vulnerability_count": len(analysis_data.get("vulnerability_confirmation", {}))
                        },
                        "vulnerabilities": [
                            {
                                "type": vuln_type,
                                "severity": vuln_data.get("severity", "unknown"),
                                "description": vuln_data.get("evidence", "")
                            }
                            for vuln_type, vuln_data in analysis_data.get("vulnerability_confirmation", {}).items()
                        ],
                        "recommendations": [
                            {
                                "issue": rec_type,
                                "solution": (
                                    f"{rec_data.get('code_level_fix', '')}\n"
                                    f"{rec_data.get('secure_coding_practices', '')}"
                                ).strip()
                            }
                            for rec_type, rec_data in analysis_data.get("remediation_suggestions", {}).items()
                        ]
                    }
                }
                
            except json.JSONDecodeError as e:
                logger.error(f"JSON解析失败: {str(e)}")
                # 如果JSON解析失败，返回原始文本
                return {
                    "status": "success",
                    "analysis": {
                        "raw_text": analysis_text,
                        "summary": self._extract_summary(analysis_text),
                        "vulnerabilities": self._extract_vulnerabilities(analysis_text),
                        "recommendations": self._extract_recommendations(analysis_text)
                    }
                }
                
        except Exception as e:
            logger.error(f"AI API调用失败: {str(e)}")
            return {
                "status": "error",
                "message": str(e)
            }

    def _extract_summary(self, text: str) -> Dict:
        """从AI响应中提取摘要信息"""
        try:
            # 使用正则表达式提取关键信息
            risk_level = re.search(r'风险等级[：:]\s*(\w+)', text)
            vuln_count = re.search(r'漏洞数量[：:]\s*(\d+)', text)
            
            return {
                "risk_level": risk_level.group(1) if risk_level else "unknown",
                "vulnerability_count": int(vuln_count.group(1)) if vuln_count else 0
            }
        except Exception:
            return {"risk_level": "unknown", "vulnerability_count": 0}

    def _extract_vulnerabilities(self, text: str) -> List[Dict]:
        """从AI响应中提取漏洞信息"""
        vulnerabilities = []
        try:
            # 使用正则表达式匹配漏洞描述块
            vuln_blocks = re.finditer(
                r'漏洞类型[：:]\s*(.+?)\n.*?严重程度[：:]\s*(.+?)\n.*?描述[：:]\s*(.+?)\n',
                text,
                re.DOTALL
            )
            
            for block in vuln_blocks:
                vulnerabilities.append({
                    "type": block.group(1).strip(),
                    "severity": block.group(2).strip(),
                    "description": block.group(3).strip()
                })
                
        except Exception:
            pass
        return vulnerabilities

    def _extract_recommendations(self, text: str) -> List[Dict]:
        """从AI响应中提取修复建议"""
        recommendations = []
        try:
            # 使用正则表达式匹配修复建议块
            rec_blocks = re.finditer(
                r'问题[：:]\s*(.+?)\n.*?修复建议[：:]\s*(.+?)\n',
                text,
                re.DOTALL
            )
            
            for block in rec_blocks:
                recommendations.append({
                    "issue": block.group(1).strip(),
                    "solution": block.group(2).strip()
                })
                
        except Exception:
            pass
        return recommendations

    def _analyze_ast(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        """分析AST结构"""
        issues = []
        try:
            # 解析代码获取AST
            ast = self._parse_code(content, file_path)
            if not ast:
                return []
                
            # 根据文件类型选择不同的访问器
            ext = os.path.splitext(file_path)[1].lower()
            if ext == '.php' or ext == '.blade.php':
                visitor = PHPASTVisitor()
            elif ext in ['.js', '.ts', '.tsx']:
                visitor = TypeScriptASTVisitor()
            else:
                return []
                
            # 访问AST节点
            issues.extend(visitor.visit(ast))
            
            # 添加文件信息
            for issue in issues:
                issue['file'] = file_path
                
            return issues
            
        except Exception as e:
            logger.error(f"AST分析失败 {file_path}: {str(e)}")
            return []
            
    def _analyze_dataflow(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        """数据流分析"""
        issues = []
        try:
            # 获取文件类型
            ext = os.path.splitext(file_path)[1].lower()
            
            # 根据文件类型进行不同的数据流分析
            if ext == '.php' or ext == '.blade.php':
                # 检查用户输入
                issues.extend(self._check_user_input(content))
                
                # 检查数据库操作
                issues.extend(self._check_database_operations(content))
                
                # 检查文件操作
                issues.extend(self._check_file_operations(content))
                
            elif ext in ['.js', '.ts', '.tsx']:
                # 检查DOM操作
                issues.extend(self._check_dom_operations(content))
                
                # 检查AJAX调用
                issues.extend(self._check_ajax_calls(content))
                
            # 添加文件信息
            for issue in issues:
                issue['file'] = file_path
                
            return issues
            
        except Exception as e:
            logger.error(f"数据流分析失败 {file_path}: {str(e)}")
            return []
            
    def _merge_issues(self, *issue_lists: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """合并并去重问题列表"""
        merged = []
        try:
            # 使用集合去重
            seen = set()
            
            for issues in issue_lists:
                for issue in issues:
                    # 创建唯一标识
                    key = (
                        issue.get('type', ''),
                        issue.get('line', 0),
                        issue.get('description', ''),
                        issue.get('file', '')
                    )
                    
                    if key not in seen:
                        seen.add(key)
                        merged.append(issue)
                        
            return merged
            
        except Exception as e:
            logger.error(f"合并问题失败: {str(e)}")
            return []
            
    def _has_sufficient_validation(self, node: Any, context: Dict) -> bool:
        """检查是否有足够的输入验证"""
        try:
            # 检查是否有输入验证
            validation_funcs = {
                'filter_var', 'filter_input', 'htmlspecialchars',
                'strip_tags', 'addslashes', 'mysql_real_escape_string'
            }
            
            # 检查前置验证
            if not isinstance(context, dict):
                return False
            
            if context.get('has_validation', False):
                return True
            
            # 检查当前节点的验证
            if isinstance(node, dict):
                calls = self._find_function_calls(node)
                for call in calls:
                    if isinstance(call, dict) and call.get('name', '') in validation_funcs:
                        return True
            
            return False
        
        except Exception as e:
            logger.error(f"检查输入验证失败: {str(e)}")
            return False

    def _find_function_calls(self, node: Dict) -> List[Dict]:
        """查找函数调用"""
        calls = []
        try:
            if isinstance(node, dict):
                if node.get('type') == 'CallExpression':
                    calls.append({
                        'name': node.get('callee', {}).get('name', ''),
                        'line': node.get('loc', {}).get('start', {}).get('line', 0)
                    })
                
                # 递归查找子节点
                for value in node.values():
                    if isinstance(value, (dict, list)):
                        calls.extend(self._find_function_calls(value))
            
            elif isinstance(node, list):
                for item in node:
                    calls.extend(self._find_function_calls(item))
        
        except Exception as e:
            logger.error(f"查找函数调用失败: {str(e)}")
        
        return calls

    def _check_user_input(self, content: str) -> List[Dict[str, Any]]:
        """检查用户输入"""
        issues = []
        try:
            # 实现用户输入检查逻辑
            # 这里可以根据需要实现不同的检查逻辑
            return issues
        except Exception as e:
            logger.error(f"检查用户输入失败: {str(e)}")
            return []

    def _check_database_operations(self, content: str) -> List[Dict[str, Any]]:
        """检查数据库操作"""
        issues = []
        try:
            # 实现数据库操作检查逻辑
            # 这里可以根据需要实现不同的检查逻辑
            return issues
        except Exception as e:
            logger.error(f"检查数据库操作失败: {str(e)}")
            return []

    def _check_file_operations(self, content: str) -> List[Dict[str, Any]]:
        """检查文件操作"""
        issues = []
        try:
            # 实现文件操作检查逻辑
            # 这里可以根据需要实现不同的检查逻辑
            return issues
        except Exception as e:
            logger.error(f"检查文件操作失败: {str(e)}")
            return []

    def _check_dom_operations(self, content: str) -> List[Dict[str, Any]]:
        """检查DOM操作"""
        issues = []
        try:
            # 实现DOM操作检查逻辑
            # 这里可以根据需要实现不同的检查逻辑
            return issues
        except Exception as e:
            logger.error(f"检查DOM操作失败: {str(e)}")
            return []

    def _check_ajax_calls(self, content: str) -> List[Dict[str, Any]]:
        """检查AJAX调用"""
        issues = []
        try:
            # 实现AJAX调用检查逻辑
            # 这里可以根据需要实现不同的检查逻辑
            return issues
        except Exception as e:
            logger.error(f"检查AJAX调用失败: {str(e)}")
            return []

    def _is_test_code(self, file_path: str) -> bool:
        """检查是否为测试代码"""
        try:
            # 实现测试代码检查逻辑
            # 这里可以根据需要实现不同的检查逻辑
            return False
        except Exception as e:
            logger.error(f"检查测试代码失败: {str(e)}")
            return False

    def _is_infinite_loop(self, ast: Any) -> bool:
        """检查是否为无限循环"""
        try:
            # 实现无限循环检查逻辑
            # 这里可以根据需要实现不同的检查逻辑
            return False
        except Exception as e:
            logger.error(f"检查无限循环失败: {str(e)}")
            return False

    def _get_context_info(self, file_path: str) -> Dict:
        """获取文件上下文信息"""
        try:
            # 实现获取文件上下文信息的逻辑
            # 这里可以根据需要实现不同的获取逻辑
            return {}
        except Exception as e:
            logger.error(f"获取文件上下文信息失败: {str(e)}")
            return {}

    def _calculate_risk_level(self, suspicious_files: List[Dict[str, Any]]) -> str:
        """计算风险等级"""
        try:
            # 实现计算风险等级的逻辑
            # 这里可以根据需要实现不同的计算逻辑
            return "unknown"
        except Exception as e:
            logger.error(f"计算风险等级失败: {str(e)}")
            return "unknown"

    def _generate_recommendations(self, suspicious_files: List[Dict[str, Any]], results: Dict[str, Any]) -> List[Dict]:
        """生成推荐建议"""
        try:
            # 实现生成推荐建议的逻辑
            # 这里可以根据需要实现不同的生成逻辑
            return []
        except Exception as e:
            logger.error(f"生成推荐建议失败: {str(e)}")
            return []

    def _simple_php_check(self, content: str) -> List[Dict[str, Any]]:
        """简单的PHP代码检查"""
        issues = []
        try:
            # 危险函数列表
            dangerous_functions = [
                'eval', 'exec', 'system', 'shell_exec', 'passthru',
                'popen', 'proc_open', 'pcntl_exec', '`', 'assert'
            ]
            
            # SQL注入风险函数
            sql_functions = [
                'mysql_query', 'mysqli_query', 'pg_query',
                'sqlite_query', 'db_query'
            ]
            
            # 文件操作风险函数
            file_functions = [
                'fopen', 'file_get_contents', 'file_put_contents',
                'unlink', 'rmdir', 'mkdir', 'rename', 'copy'
            ]
            
            # 按行检查代码
            lines = content.split('\n')
            for i, line in enumerate(lines, 1):
                # 检查危险函数
                for func in dangerous_functions:
                    if f"{func}(" in line:
                        issues.append({
                            'type': 'dangerous_function',
                            'line': i,
                            'description': f'发现危险函数: {func}',
                            'severity': 'high'
                        })
                        
                # 检查SQL注入风险
                for func in sql_functions:
                    if f"{func}(" in line and '$_' in line:
                        issues.append({
                            'type': 'sql_injection',
                            'line': i,
                            'description': f'可能的SQL注入风险: {func}',
                            'severity': 'high'
                        })
                        
                # 检查文件操作风险
                for func in file_functions:
                    if f"{func}(" in line and '$_' in line:
                        issues.append({
                            'type': 'file_operation',
                            'line': i,
                            'description': f'不安全的文件操作: {func}',
                            'severity': 'medium'
                        })
                        
            return issues
            
        except Exception as e:
            logger.error(f"PHP代码检查失败: {str(e)}")
            return []
            
    def _simple_js_check(self, content: str) -> List[Dict[str, Any]]:
        """简单的JavaScript代码检查"""
        issues = []
        try:
            # 危险函数列表
            dangerous_functions = [
                'eval', 'Function', 'setTimeout', 'setInterval',
                'execScript', 'document.write'
            ]
            
            # XSS风险函数
            xss_functions = [
                'innerHTML', 'outerHTML', 'insertAdjacentHTML',
                'document.write', 'document.writeln'
            ]
            
            # 按行检查代码
            lines = content.split('\n')
            for i, line in enumerate(lines, 1):
                # 检查危险函数
                for func in dangerous_functions:
                    if func in line:
                        issues.append({
                            'type': 'dangerous_function',
                            'line': i,
                            'description': f'发现危险函数: {func}',
                            'severity': 'high'
                        })
                        
                # 检查XSS风险
                for func in xss_functions:
                    if func in line:
                        issues.append({
                            'type': 'xss',
                            'line': i,
                            'description': f'可能的XSS风险: {func}',
                            'severity': 'high'
                        })
                        
            return issues
            
        except Exception as e:
            logger.error(f"JavaScript代码检查失败: {str(e)}")
            return []
            
    def _simple_code_check(self, content: str) -> List[Dict[str, Any]]:
        """通用代码检查"""
        issues = []
        try:
            # 通用危险模式
            dangerous_patterns = [
                (r'password\s*=\s*[\'"][^\'"]+[\'"]', '硬编码密码'),
                (r'api[_-]?key\s*=\s*[\'"][^\'"]+[\'"]', '硬编码API密钥'),
                (r'secret[_-]?key\s*=\s*[\'"][^\'"]+[\'"]', '硬编码密钥'),
                (r'token\s*=\s*[\'"][^\'"]+[\'"]', '硬编码令牌')
            ]
            
            # 按行检查代码
            lines = content.split('\n')
            for i, line in enumerate(lines, 1):
                # 检查危险模式
                for pattern, desc in dangerous_patterns:
                    if re.search(pattern, line, re.I):
                        issues.append({
                            'type': 'sensitive_data',
                            'line': i,
                            'description': f'发现敏感信息: {desc}',
                            'severity': 'medium'
                        })
                        
            return issues
            
        except Exception as e:
            logger.error(f"通用代码检查失败: {str(e)}")
            return []

    def _read_file_content(self, file_path: str) -> Optional[str]:
        """读取文件内容"""
        try:
            # 尝试使用UTF-8编码读取
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                    if content:
                        logger.debug(f"成功读取文件(UTF-8): {file_path}")
                        return content
            except UnicodeDecodeError:
                # 如果UTF-8失败，尝试GBK编码
                with open(file_path, 'r', encoding='gbk') as f:
                    content = f.read()
                    if content:
                        logger.debug(f"成功读取文件(GBK): {file_path}")
                        return content
                        
            logger.warning(f"文件内容为空: {file_path}")
            return None
            
        except Exception as e:
            logger.error(f"读取文件失败 {file_path}: {str(e)}")
            return None