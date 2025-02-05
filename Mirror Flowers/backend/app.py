from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, validator
from openai import AsyncOpenAI
import os
from typing import List, Optional, Dict, Set, Tuple
import aiohttp
import logging
from pydantic_settings import BaseSettings
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from enum import Enum
from urllib.parse import urlparse
import asyncio
import zipfile
from pathlib import Path
import tempfile
import json

# 配置类
class ModelType(str, Enum):
    GPT35 = "gpt-3.5-turbo"
    GPT4 = "gpt-4"
    CLAUDE = "claude-2"
    CLAUDE3 = "claude-3"

class Settings(BaseSettings):
    OPENAI_API_KEY: str = "sk-LshpT3NTpaT3HDw317634b552f22499c9aE9E75e003b9fA3"
    OPENAI_API_BASE: str = "https://free.v36.cm/v1"
    OPENAI_MODEL: str = "gpt-4o-mini-2024-07-18"
    
    # 更新可用模型配置，按域名和类型分组
    AVAILABLE_MODELS: Dict[str, Dict[str, List[str]]] = {
        "guji.ai": {
            "Chat": [
                "gpt-3.5-turbo",
                "gpt-3.5-turbo-1106",
                "gpt-3.5-turbo-0125",
                "gpt-3.5-turbo-16k",
                "gpt-4",
                "gpt-4-1106-preview",
                "gpt-4-0125-preview",
                "gpt-4-32k",
                "claude-2",
                "claude-3",
                "01-ai/Yi-1.5-6B-Chat",
                "01-ai/Yi-1.5-9B-Chat-16K",
                "01-ai/Yi-1.5-34B-Chat-16K",
                "THUDM/chatglm3-6b",
                "THUDM/glm-4-9b-chat",
                "Qwen/Qwen2-7B-Instruct",
                "Qwen/Qwen2-1.5B-Instruct",
                "internlm/internlm2_5-7b-chat"
            ],
            "Embedding": [
                "BAAI/bge-large-en-v1.5",
                "BAAI/bge-large-zh-v1.5",
                "BAAI/bge-m3",
                "netease-youdao/bce-embedding-base_v1"
            ],
            "Image": [
                "stabilityai/stable-diffusion-xl-base-1.0",
                "stabilityai/stable-diffusion-2-1",
                "stabilityai/stable-diffusion-3-medium",
                "stabilityai/stable-diffusion-3-5-large",
                "stabilityai/stable-diffusion-3-5-large-turbo"
            ],
            "Audio": [
                "FunAudioLLM/SenseVoiceSmall",
                "fishaudio/fish-speech-1.4",
                "fishaudio/fish-speech-1.5",
                "FunAudioLLM/CosyVoice2-0.5B"
            ],
            "Pro": [
                "Pro/Qwen/Qwen2-7B-Instruct",
                "Pro/Qwen/Qwen2-1.5B-Instruct",
                "Pro/THUDM/glm-4-9b-chat",
                "Pro/BAAI/bge-m3",
                "Pro/OpenGVLab/InternVL2-8B"
            ]
        },
        "360.com": {
            "Chat": [
                "360GPT_S2_V9",
                "360GPT_S2_V9.4",
                "360GPT_S2_V9.4-4K",
                "360GPT_S2_V9.4-8K"
            ]
        },
        "v36.cm": {
            "Chat": [
                "360GPT_S2_V9",
                "360GPT_S2_V9.4",
                "360GPT_S2_V9.4-4K",
                "360GPT_S2_V9.4-8K"
            ]
        },
        "api.siliconflow.cn": {
            "Chat": [
                "gpt-3.5-turbo",
                "gpt-3.5-turbo-1106",
                "gpt-3.5-turbo-0125",
                "gpt-3.5-turbo-16k",
                "gpt-4",
                "gpt-4-1106-preview",
                "gpt-4-0125-preview",
                "gpt-4-32k",
                "claude-2",
                "claude-3",
                "360GPT_S2_V9",
                "360GPT_S2_V9.4",
                "360GPT_S2_V9.4-4K",
                "360GPT_S2_V9.4-8K",
                "01-ai/Yi-1.5-6B-Chat",
                "01-ai/Yi-1.5-9B-Chat-16K",
                "01-ai/Yi-1.5-34B-Chat-16K",
                "THUDM/chatglm3-6b",
                "THUDM/glm-4-9b-chat",
                "Qwen/Qwen2-7B-Instruct",
                "Qwen/Qwen2-1.5B-Instruct",
                "internlm/internlm2_5-7b-chat"
            ]
        }
    }
    
    @validator('OPENAI_API_BASE')
    def validate_api_base(cls, v):
        v = v.rstrip('/')
        if not v.endswith('/v1'):
            v = v + '/v1'
        return v

    async def fetch_models_from_api(self, api_base: str, api_key: str) -> Dict[str, List[str]]:
        """从API获取可用模型列表"""
        try:
            async with aiohttp.ClientSession() as session:
                headers = {
                    "Authorization": f"Bearer {api_key}",
                    "Content-Type": "application/json"
                }
                async with session.get(f"{api_base}/models", headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        models = data.get("data", [])
                        
                        # 按类型分组模型
                        grouped_models = {
                            "Chat": [],
                            "Embedding": [],
                            "Image": [],
                            "Audio": [],
                            "Pro": []
                        }
                        
                        for model in models:
                            model_id = model.get("id")
                            if not model_id:
                                continue
                                
                            # 根据模型ID分类
                            if model_id.startswith("360GPT"):
                                grouped_models["Chat"].append(model_id)
                            elif "embedding" in model_id.lower():
                                grouped_models["Embedding"].append(model_id)
                            elif any(img_key in model_id.lower() for img_key in ["diffusion", "dall-e"]):
                                grouped_models["Image"].append(model_id)
                            elif any(audio_key in model_id.lower() for audio_key in ["speech", "voice", "audio"]):
                                grouped_models["Audio"].append(model_id)
                            elif model_id.startswith("Pro/"):
                                grouped_models["Pro"].append(model_id)
                            else:
                                grouped_models["Chat"].append(model_id)
                        
                        # 移除空类别
                        return {k: v for k, v in grouped_models.items() if v}
                    else:
                        error_data = await response.text()
                        logger.error(f"获取模型列表失败: {error_data}")
                        return self.get_default_models(api_base)
                        
        except Exception as e:
            logger.error(f"获取模型列表时出错: {str(e)}")
            return self.get_default_models(api_base)

    def get_default_models(self, api_base: str) -> Dict[str, List[str]]:
        """根据API地址获取默认模型列表"""
        try:
            parsed_url = urlparse(api_base)
            domain = parsed_url.netloc.lower()
            
            # 提取基本域名
            base_domain = '.'.join(domain.split('.')[-2:])
            
            # 尝试直接匹配域名
            if domain in self.AVAILABLE_MODELS:
                logger.info(f"直接匹配到域名: {domain}")
                return self.AVAILABLE_MODELS[domain]
            
            # 尝试匹配基本域名
            if base_domain in self.AVAILABLE_MODELS:
                logger.info(f"匹配到基本域名: {base_domain}")
                return self.AVAILABLE_MODELS[base_domain]
            
            # 尝试部分匹配
            for configured_domain in self.AVAILABLE_MODELS.keys():
                if (configured_domain in domain or 
                    domain in configured_domain or 
                    configured_domain in base_domain or 
                    base_domain in configured_domain):
                    logger.info(f"部分匹配到域名: {configured_domain}")
                    return self.AVAILABLE_MODELS[configured_domain]
            
            # 如果是特定域名，返回对应配置
            if "v36.cm" in domain:
                logger.info("匹配到 v36.cm 域名")
                return self.AVAILABLE_MODELS["v36.cm"]
            if "360.com" in domain:
                logger.info("匹配到 360.com 域名")
                return self.AVAILABLE_MODELS["360.com"]
            if "siliconflow.cn" in domain:
                logger.info("匹配到 siliconflow.cn 域名")
                return self.AVAILABLE_MODELS["api.siliconflow.cn"]
            
            logger.warning(f"未找到匹配的域名配置: {domain}")
            return {"Chat": ["gpt-3.5-turbo"]}
            
        except Exception as e:
            logger.error(f"获取默认模型列表时出错: {str(e)}")
            return {"Chat": ["gpt-3.5-turbo"]}

    async def get_models_for_api(self, api_base: str, api_key: str = None) -> Dict[str, List[str]]:
        """获取指定API地址支持的模型列表"""
        try:
            # 尝试从API获取模型列表
            if api_key:
                try:
                    models = await self.fetch_models_from_api(api_base, api_key)
                    if models:
                        logger.info(f"从API获取到模型列表: {models}")
                        return models
                except Exception as e:
                    logger.warning(f"从API获取模型列表失败: {str(e)}")
            
            # 如果API获取失败，使用预配置的模型列表
            return self.get_default_models(api_base)
            
        except Exception as e:
            logger.error(f"获取模型列表时出错: {str(e)}")
            return {"Chat": ["gpt-3.5-turbo"]}

    class Config:
        env_file = ".env"
        case_sensitive = True

settings = Settings()

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = FastAPI(title="代码审计工具API")

# 配置CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 挂载静态文件目录（如果前端文件在static目录下）
static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

# 添加新的数据模型
class ProjectAuditResult(BaseModel):
    file_path: str
    language: str
    vulnerabilities: List[dict]
    related_files: List[str]
    context_analysis: str

class ProjectAnalysis:
    def __init__(self):
        self.file_dependencies: Dict[str, Set[str]] = {}  # 文件依赖关系
        self.shared_variables: Dict[str, Set[str]] = {}   # 共享变量
        self.function_calls: Dict[str, Set[str]] = {}     # 函数调用关系
        self.vulnerability_context: Dict[str, List[dict]] = {}  # 漏洞上下文

    def add_dependency(self, file: str, depends_on: str):
        if file not in self.file_dependencies:
            self.file_dependencies[file] = set()
        self.file_dependencies[file].add(depends_on)

    def add_shared_variable(self, file: str, variable: str):
        if file not in self.shared_variables:
            self.shared_variables[file] = set()
        self.shared_variables[file].add(variable)

    def add_function_call(self, source_file: str, target_file: str):
        if source_file not in self.function_calls:
            self.function_calls[source_file] = set()
        self.function_calls[source_file].add(target_file)

    def get_related_files(self, file: str) -> Set[str]:
        """获取与指定文件相关的所有文件"""
        related = set()
        if file in self.file_dependencies:
            related.update(self.file_dependencies[file])
        if file in self.function_calls:
            related.update(self.function_calls[file])
        return related

class CodeAuditService:
    def __init__(self):
        """初始化服务"""
        self.client = None
        self.openai_api_key = None
        self.api_base = None
        self.model = None
        # 初始化时设置基本配置，但不进行异步操作
        self._init_config(settings.OPENAI_API_KEY, settings.OPENAI_API_BASE)
        self.project_analysis = ProjectAnalysis()
        self.supported_extensions = {'.php', '.java', '.js', '.py'}
    
    def _init_config(self, api_key: str, api_base: str):
        """初始化基本配置"""
        self.openai_api_key = api_key
        self.api_base = api_base.rstrip('/') + '/v1' if not api_base.endswith('/v1') else api_base
        self.model = "gpt-3.5-turbo"  # 设置默认模型
    
    async def ensure_initialized(self):
        """确保服务完全初始化"""
        if not self.client:
            await self.configure_openai(self.openai_api_key, self.api_base)

    async def configure_openai(self, api_key: str = None, api_base: str = None, model: str = None):
        """配置OpenAI API设置"""
        if not api_key and not self.openai_api_key:
            raise ValueError("未设置OPENAI_API_KEY")
        
        # 更新配置
        if api_key:
            self.openai_api_key = api_key
        if api_base:
            api_base = api_base.rstrip('/')
            if not api_base.endswith('/v1'):
                api_base = api_base + '/v1'
            self.api_base = api_base
        elif not self.api_base:
            self.api_base = settings.OPENAI_API_BASE

        # 获取当前API地址支持的模型列表
        available_models = await settings.get_models_for_api(self.api_base, self.openai_api_key)
        
        # 设置模型
        if model:
            model_found = False
            for category_models in available_models.values():
                if model in category_models:
                    self.model = model
                    model_found = True
                    break
            if not model_found:
                raise ValueError(f"该API地址不支持模型: {model}")
        elif not self.model:
            if "Chat" in available_models and available_models["Chat"]:
                self.model = available_models["Chat"][0]
            else:
                first_category = next(iter(available_models))
                if available_models[first_category]:
                    self.model = available_models[first_category][0]
                else:
                    self.model = "gpt-3.5-turbo"

        try:
            self.client = AsyncOpenAI(
                api_key=self.openai_api_key,
                base_url=self.api_base,
                timeout=120.0,  # 增加超时时间到120秒
                max_retries=5   # 增加重试次数
            )
            logger.info(f"OpenAI API已配置: {self.api_base}, 使用模型: {self.model}")
        except Exception as e:
            logger.error(f"OpenAI客户端配置失败: {str(e)}")
            raise ValueError(f"API配置失败: {str(e)}")
    
    async def analyze_code(self, code: str, language: str, api_key: str = None, api_base: str = None) -> dict:
        """分析代码，支持自定义API设置"""
        try:
            # 如果提供了新的API设置，重新配置
            if api_key or api_base:
                self.configure_openai(api_key, api_base)
            
            # 第一轮AI分析
            logger.info(f"开始第一轮{language}代码分析")
            first_response = await self._get_openai_response(
                self._generate_first_prompt(code, language)
            )
            
            # 第二轮AI验证
            logger.info("开始第二轮验证分析")
            second_response = await self._get_openai_response(
                self._generate_second_prompt(code, first_response)
            )
            
            return {
                "first_analysis": first_response,
                "second_analysis": second_response
            }
        except Exception as e:
            logger.error(f"代码分析过程中发生错误: {str(e)}")
            raise HTTPException(status_code=500, detail=str(e))
    
    def _generate_first_prompt(self, code: str, language: str) -> str:
        return f"""请分析以下{language}代码中的安全漏洞：
        {code}
        请详细说明每个潜在的安全问题，包括：
        1. 漏洞类型
        2. 漏洞位置
        3. 可能的影响
        4. 修复建议"""
    
    def _generate_second_prompt(self, code: str, first_response: str) -> str:
        return f"""请验证以下代码审计结果的准确性，并提供可能的payload：
        {first_response}
        代码：
        {code}"""
    
    async def _get_openai_response(self, prompt: str) -> str:
        if not self.client:
            raise ValueError("OpenAI客户端未初始化")

        try:
            logger.info(f"正在发送请求到: {self.api_base}, 使用模型: {self.model}")
            
            # 添加重试逻辑
            max_retries = 3
            retry_count = 0
            retry_delay = 1  # 初始延迟1秒

            while retry_count < max_retries:
                try:
                    response = await self.client.chat.completions.create(
                        model=self.model,
                        messages=[
                            {"role": "system", "content": "你是一个专业的代码安全审计专家。"},
                            {"role": "user", "content": prompt}
                        ],
                        temperature=0.7,
                        max_tokens=2000
                    )
                    
                    if hasattr(response, 'choices') and len(response.choices) > 0:
                        content = response.choices[0].message.content
                        logger.debug(f"收到响应: {content[:100]}...")
                        return content
                    else:
                        raise ValueError("API响应格式错误")

                except Exception as e:
                    retry_count += 1
                    if retry_count >= max_retries:
                        raise
                    
                    logger.warning(f"请求失败，正在进行第{retry_count}次重试: {str(e)}")
                    await asyncio.sleep(retry_delay)
                    retry_delay *= 2  # 指数退避
            
        except Exception as e:
            error_msg = str(e)
            logger.error(f"OpenAI API调用失败: {error_msg}")
            
            if "401" in error_msg:
                raise HTTPException(status_code=401, detail="API密钥无效或未授权")
            elif "timeout" in error_msg.lower():
                raise HTTPException(status_code=504, detail="API请求超时，请稍后重试")
            elif "404" in error_msg:
                raise HTTPException(status_code=404, detail="API端点不存在，请检查API基础URL")
            else:
                raise HTTPException(status_code=500, detail=f"AI分析服务错误: {error_msg}")

    async def analyze_project(self, zip_file: UploadFile) -> Dict[str, ProjectAuditResult]:
        """分析整个项目代码"""
        results = {}
        
        # 创建临时目录
        with tempfile.TemporaryDirectory() as temp_dir:
            # 保存并解压ZIP文件
            zip_path = Path(temp_dir) / "project.zip"
            with open(zip_path, "wb") as f:
                content = await zip_file.read()
                f.write(content)
            
            # 解压文件
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                zip_ref.extractall(temp_dir)
            
            # 首先进行项目结构分析
            await self._analyze_project_structure(temp_dir)
            
            # 分析每个文件
            for file_path in Path(temp_dir).rglob('*'):
                if file_path.suffix in self.supported_extensions:
                    rel_path = str(file_path.relative_to(temp_dir))
                    try:
                        result = await self._analyze_file_with_context(
                            file_path, 
                            self.project_analysis.get_related_files(rel_path)
                        )
                        results[rel_path] = result
                    except Exception as e:
                        logger.error(f"分析文件 {rel_path} 时出错: {str(e)}")
        
        # 进行交叉验证和上下文关联分析
        await self._cross_validate_results(results)
        
        return results

    async def _analyze_project_structure(self, project_dir: str):
        """分析项目结构，建立依赖关系"""
        for file_path in Path(project_dir).rglob('*'):
            if file_path.suffix not in self.supported_extensions:
                continue
                
            rel_path = str(file_path.relative_to(project_dir))
            content = file_path.read_text(errors='ignore')
            
            # 分析文件依赖
            await self._analyze_dependencies(rel_path, content)
            
            # 分析共享变量
            await self._analyze_shared_variables(rel_path, content)
            
            # 分析函数调用
            await self._analyze_function_calls(rel_path, content)

    async def _analyze_file_with_context(
        self, 
        file_path: Path, 
        related_files: Set[str]
    ) -> ProjectAuditResult:
        """分析单个文件，考虑上下文"""
        content = file_path.read_text(errors='ignore')
        language = file_path.suffix[1:]  # 移除点号
        
        # 构建包含上下文的提示
        context_prompt = f"""请分析以下{language}代码，重点关注安全漏洞。请提供详细的JSON格式分析结果：

代码内容：
{content}

相关文件：
{', '.join(related_files)}

请提供以下格式的分析结果：
{{
    "vulnerabilities": [
        {{
            "type": "漏洞类型（如SQL注入、XSS等）",
            "location": "具体代码行号和代码片段",
            "severity": "严重程度（高/中/低）",
            "description": "详细的漏洞描述",
            "impact": "潜在影响",
            "fix": "修复建议",
            "related_context": "相关的上下文信息"
        }}
    ],
    "context_analysis": "整体代码安全性分析",
    "related_files": {{
        "dependencies": ["相关的依赖文件"],
        "includes": ["包含的文件"],
        "functions": ["调用的函数"],
        "affected_by": ["受影响的文件"],
        "affects": ["可能影响的文件"]
    }}
}}

请特别注意：
1. 详细分析每个可能的漏洞
2. 提供具体的代码位置
3. 给出可行的修复建议
4. 分析代码与其他文件的关联
5. 考虑整体的安全影响
"""
        
        # 获取AI分析结果
        analysis_result = await self._get_openai_response(context_prompt)
        
        # 解析结果
        try:
            result_dict = json.loads(analysis_result)
            
            # 确保结果包含所有必要字段
            if 'vulnerabilities' not in result_dict:
                result_dict['vulnerabilities'] = []
            if 'context_analysis' not in result_dict:
                result_dict['context_analysis'] = "未提供分析结果"
            if 'related_files' not in result_dict:
                result_dict['related_files'] = {
                    "dependencies": [],
                    "includes": [],
                    "functions": [],
                    "affected_by": [],
                    "affects": []
                }
            
            # 转换相关文件格式
            related_files_list = []
            for category, files in result_dict['related_files'].items():
                if files:
                    related_files_list.extend([f"{category}: {file}" for file in files])
            
            return ProjectAuditResult(
                file_path=str(file_path),
                language=language,
                vulnerabilities=result_dict['vulnerabilities'],
                related_files=related_files_list,
                context_analysis=result_dict['context_analysis']
            )
        except json.JSONDecodeError:
            # 如果结果不是JSON格式，返回基本结构
            return ProjectAuditResult(
                file_path=str(file_path),
                language=language,
                vulnerabilities=[],
                related_files=[],
                context_analysis=analysis_result
            )

    async def _cross_validate_results(self, results: Dict[str, ProjectAuditResult]):
        """交叉验证分析结果"""
        # 收集所有漏洞
        all_vulnerabilities = []
        for result in results.values():
            all_vulnerabilities.extend(result.vulnerabilities)
        
        # 生成交叉验证提示
        validation_prompt = f"""请验证以下项目漏洞分析结果的准确性和完整性：

发现的漏洞：
{json.dumps(all_vulnerabilities, indent=2, ensure_ascii=False)}

请考虑：
1. 漏洞之间的关联性
2. 漏洞的优先级
3. 误报可能性
4. 修复建议的可行性
"""
        
        # 获取验证结果
        validation_result = await self._get_openai_response(validation_prompt)
        
        # 更新结果
        for result in results.values():
            result.context_analysis += f"\n\n交叉验证结果：\n{validation_result}"

    async def _analyze_dependencies(self, file_path: str, content: str):
        """分析文件依赖关系"""
        try:
            language = Path(file_path).suffix[1:]
            
            # 根据不同语言分析依赖
            if language == 'php':
                await self._analyze_php_dependencies(file_path, content)
            elif language == 'java':
                await self._analyze_java_dependencies(file_path, content)
            elif language == 'py':
                await self._analyze_python_dependencies(file_path, content)
            elif language == 'js':
                await self._analyze_js_dependencies(file_path, content)
                
        except Exception as e:
            logger.error(f"分析文件依赖时出错 {file_path}: {str(e)}")

    async def _analyze_php_dependencies(self, file_path: str, content: str):
        """分析PHP文件依赖"""
        import re
        patterns = [
            r'(?:include|require|include_once|require_once)\s*[\'"]([^\'"]+)[\'"]',
            r'use\s+([^;]+)',
            r'namespace\s+([^;{\s]+)'
        ]
        
        for pattern in patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                dependency = match.group(1)
                self.project_analysis.add_dependency(file_path, dependency)

    async def _analyze_java_dependencies(self, file_path: str, content: str):
        """分析Java文件依赖"""
        import re
        patterns = [
            r'import\s+([^;]+)',
            r'extends\s+([^\s{]+)',
            r'implements\s+([^{]+)'
        ]
        
        for pattern in patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                dependency = match.group(1)
                self.project_analysis.add_dependency(file_path, dependency)

    async def _analyze_python_dependencies(self, file_path: str, content: str):
        """分析Python文件依赖"""
        import re
        patterns = [
            r'(?:from|import)\s+([^\s]+)',
            r'__import__\([\'"]([^\'"]+)[\'"]\)'
        ]
        
        for pattern in patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                dependency = match.group(1)
                self.project_analysis.add_dependency(file_path, dependency)

    async def _analyze_js_dependencies(self, file_path: str, content: str):
        """分析JavaScript文件依赖"""
        import re
        patterns = [
            r'(?:import|require)\s*\([\'"]([^\'"]+)[\'"]\)',
            r'import\s+.*\s+from\s+[\'"]([^\'"]+)[\'"]',
            r'import\s+[\'"]([^\'"]+)[\'"]'
        ]
        
        for pattern in patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                dependency = match.group(1)
                self.project_analysis.add_dependency(file_path, dependency)

    async def _analyze_shared_variables(self, file_path: str, content: str):
        """分析共享变量"""
        try:
            language = Path(file_path).suffix[1:]
            
            # 根据不同语言分析共享变量
            if language == 'php':
                await self._analyze_php_shared_vars(file_path, content)
            elif language == 'java':
                await self._analyze_java_shared_vars(file_path, content)
            elif language == 'py':
                await self._analyze_python_shared_vars(file_path, content)
            elif language == 'js':
                await self._analyze_js_shared_vars(file_path, content)
                
        except Exception as e:
            logger.error(f"分析共享变量时出错 {file_path}: {str(e)}")

    async def _analyze_php_shared_vars(self, file_path: str, content: str):
        """分析PHP共享变量"""
        import re
        patterns = [
            r'\$GLOBALS\[[\'"](\w+)[\'"]\]',
            r'\$_(?:GET|POST|REQUEST|SESSION|COOKIE)\[[\'"](\w+)[\'"]\]',
            r'global\s+\$(\w+)'
        ]
        
        for pattern in patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                var_name = match.group(1)
                self.project_analysis.add_shared_variable(file_path, var_name)

    async def _analyze_java_shared_vars(self, file_path: str, content: str):
        """分析Java共享变量"""
        import re
        patterns = [
            r'static\s+(?:final\s+)?(?:\w+)\s+(\w+)',
            r'public\s+(?:static\s+)?(?:\w+)\s+(\w+)'
        ]
        
        for pattern in patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                var_name = match.group(1)
                self.project_analysis.add_shared_variable(file_path, var_name)

    async def _analyze_python_shared_vars(self, file_path: str, content: str):
        """分析Python共享变量"""
        import re
        patterns = [
            r'global\s+(\w+)',
            r'(\w+)\s*=\s*[^=]'  # 简单的全局变量定义
        ]
        
        for pattern in patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                var_name = match.group(1)
                self.project_analysis.add_shared_variable(file_path, var_name)

    async def _analyze_js_shared_vars(self, file_path: str, content: str):
        """分析JavaScript共享变量"""
        import re
        patterns = [
            r'(?:var|let|const)\s+(\w+)\s*=',
            r'window\.(\w+)\s*=',
            r'global\.(\w+)\s*='
        ]
        
        for pattern in patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                var_name = match.group(1)
                self.project_analysis.add_shared_variable(file_path, var_name)

    async def _analyze_function_calls(self, file_path: str, content: str):
        """分析函数调用关系"""
        try:
            language = Path(file_path).suffix[1:]
            
            # 根据不同语言分析函数调用
            if language == 'php':
                await self._analyze_php_function_calls(file_path, content)
            elif language == 'java':
                await self._analyze_java_function_calls(file_path, content)
            elif language == 'py':
                await self._analyze_python_function_calls(file_path, content)
            elif language == 'js':
                await self._analyze_js_function_calls(file_path, content)
                
        except Exception as e:
            logger.error(f"分析函数调用时出错 {file_path}: {str(e)}")

    async def _analyze_php_function_calls(self, file_path: str, content: str):
        """分析PHP函数调用"""
        import re
        pattern = r'(?:function\s+(\w+)|(\w+)\s*\()'
        
        matches = re.finditer(pattern, content)
        for match in matches:
            func_name = match.group(1) or match.group(2)
            # 在项目中查找调用此函数的文件
            await self._find_function_callers(file_path, func_name)

    async def _analyze_java_function_calls(self, file_path: str, content: str):
        """分析Java函数调用"""
        import re
        pattern = r'(?:public|private|protected)?\s*(?:static)?\s*\w+\s+(\w+)\s*\([^)]*\)'
        
        matches = re.finditer(pattern, content)
        for match in matches:
            func_name = match.group(1)
            await self._find_function_callers(file_path, func_name)

    async def _analyze_python_function_calls(self, file_path: str, content: str):
        """分析Python函数调用"""
        import re
        pattern = r'def\s+(\w+)\s*\('
        
        matches = re.finditer(pattern, content)
        for match in matches:
            func_name = match.group(1)
            await self._find_function_callers(file_path, func_name)

    async def _analyze_js_function_calls(self, file_path: str, content: str):
        """分析JavaScript函数调用"""
        import re
        pattern = r'(?:function\s+(\w+)|(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?function)'
        
        matches = re.finditer(pattern, content)
        for match in matches:
            func_name = match.group(1) or match.group(2)
            await self._find_function_callers(file_path, func_name)

    async def _find_function_callers(self, source_file: str, function_name: str):
        """查找调用指定函数的文件"""
        # 这里可以实现更复杂的函数调用分析
        # 当前简单记录函数定义所在文件
        self.project_analysis.add_function_call(source_file, function_name)

code_audit_service = CodeAuditService()

# 添加请求体模型
class ConfigureRequest(BaseModel):
    api_key: str
    api_base: Optional[str] = None
    model: Optional[str] = None  # 添加模型选择

# 添加获取可用模型的API
@app.get("/api/models")
async def get_available_models():
    """获取当前API地址支持的模型列表"""
    try:
        # 确保服务已初始化
        await code_audit_service.ensure_initialized()
        
        api_base = code_audit_service.api_base or settings.OPENAI_API_BASE
        available_models = await settings.get_models_for_api(
            api_base,
            code_audit_service.openai_api_key or settings.OPENAI_API_KEY
        )
        current_model = code_audit_service.model or settings.OPENAI_MODEL
        
        logger.info(f"当前API地址: {api_base}")
        logger.info(f"可用模型: {available_models}")
        logger.info(f"当前使用的模型: {current_model}")
        
        return {
            "models": available_models,
            "current_model": current_model
        }
    except Exception as e:
        logger.error(f"获取模型列表失败: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

# 修改配置路由
@app.post("/api/configure")
async def configure_api(config: ConfigureRequest):
    """配置OpenAI API设置"""
    try:
        await code_audit_service.configure_openai(
            config.api_key, 
            config.api_base,
            config.model
        )
        return {
            "status": "success", 
            "message": "API配置已更新",
            "model": code_audit_service.model
        }
    except Exception as e:
        logger.error(f"配置更新失败: {str(e)}")
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/audit")
async def audit_code(
    file: UploadFile = File(...),
    api_key: str = None,
    api_base: str = None
):
    """审计代码，支持自定义API设置"""
    try:
        # 确保服务已初始化
        await code_audit_service.ensure_initialized()
        
        content = await file.read()
        code = content.decode()
        
        file_extension = file.filename.split('.')[-1].lower()
        if file_extension not in ['php', 'java']:
            raise HTTPException(status_code=400, detail="仅支持PHP和Java文件")
        
        language = "php" if file_extension == "php" else "java"
        logger.info(f"开始分析{file.filename}")
        
        result = await code_audit_service.analyze_code(code, language, api_key, api_base)
        return result
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="文件编码错误")
    except Exception as e:
        logger.error(f"处理文件时发生错误: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/audit/project")
async def audit_project(
    project: UploadFile = File(...),
    api_key: str = None,
    api_base: str = None
):
    """审计整个项目代码"""
    try:
        # 确保服务已初始化
        await code_audit_service.ensure_initialized()
        
        # 验证文件类型
        if not project.filename.endswith('.zip'):
            raise HTTPException(status_code=400, detail="请上传ZIP格式的项目文件")
        
        # 分析项目
        results = await code_audit_service.analyze_project(project)
        
        return {
            "status": "success",
            "results": results
        }
    except Exception as e:
        logger.error(f"项目审计过程中发生错误: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

@app.get("/")
async def root():
    """
    根路径处理程序，返回API基本信息
    """
    return {
        "name": "代码审计工具API",
        "version": "1.0.0",
        "status": "running",
        "endpoints": {
            "audit": "/api/audit",
            "configure": "/api/configure",
            "health": "/health",
            "docs": "/docs"
        }
    }

@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    """
    全局异常处理
    """
    error_msg = str(exc)
    logger.error(f"发生错误: {error_msg}")
    return JSONResponse(
        status_code=500,
        content={
            "error": "内部服务器错误",
            "detail": error_msg
        }
    )

@app.middleware("http")
async def log_requests(request, call_next):
    """
    请求日志中间件
    """
    logger.info(f"收到请求: {request.method} {request.url}")
    response = await call_next(request)
    logger.info(f"响应状态码: {response.status_code}")
    return response

@app.get("/ui")
async def serve_spa():
    """
    服务前端单页应用
    """
    return FileResponse(os.path.join(static_dir, "index.html")) 