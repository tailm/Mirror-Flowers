# Mirror Flowers (镜花) - AI 驱动的代码安全审计工具

Mirror Flowers 是一个基于 AI 的代码安全审计工具，能够自动检测代码中的安全漏洞并提供详细的分析和修复建议。

## 特性

- 支持多种编程语言（PHP、Python、Java、JavaScript）
- 本地静态代码分析
- AI 驱动的漏洞验证和分析
- 详细的安全报告和修复建议
- 支持单文件和项目文件夹分析
- 深色/浅色主题切换
- 实时分析进度显示

## API 配置说明

配置文件位置: `config/api_config.json`


```json

{

    "api_key": "sk-",

    "api_base": "https://api.deepseek.com/",

    "model": "deepseek-chat"

}

```


## 安装和配置

### 环境要求
- Python 3.8+
- FastAPI
- Node.js (前端开发)

### 快速开始

1. 克隆项目
```bash
git clone https://github.com/Ky0toFu/Mirror-Flowers.git
cd Mirror-Flowers
```

2. 安装依赖（选择以下任一方式）

```bash
pip install -r requirements.txt
```


3. 启动服务
```bash
uvicorn backend.app:app --reload
```

4. 访问Mirror-Flowers
```bash
http://localhost:8000/ui
```

## 访问
- Web 界面：http://127.0.0.1:8000/ui
- API 文档：http://127.0.0.1:8000/docs

## 使用方法

1. 访问 Web 界面
2. 配置更新 API
3. 选择分析模式（单文件/项目文件夹）
4. 上传代码文件
5. 等待分析完成
6. 查看分析结果和 AI 建议

## 支持的文件类型

- PHP: `.php`
- Python: `.py`, `.pyw`
- Java: `.java`, `.jsp`
- JavaScript: `.js`, `.jsx`, `.ts`, `.tsx`
- 辅助文件: `.html`, `.css`, `.json`, `.xml`, `.yml`, `.yaml`

## 贡献

欢迎提交 Pull Requests 和 Issues。

## 注意事项
1. API密钥安全：请妥善保管API密钥
2. 分析时间：大型项目可能需要较长时间
3. 结果验证：建议结合人工审查
4. API配置问题：如果提示"API配置更新错误"或"不存在某个模型"，请检查API Base URL格式，尝试在URL后添加/v1或删除/v1（例如：https://api.example.com 或 https://api.example.com/v1）


## 项目结构
```
Mirror-Flowers/
├── frontend/          # Vue.js前端
├── backend/           # Python FastAPI后端
│   ├── static/        # 静态资源文件
│   ├── services/      # 业务逻辑服务
│   └── config.py      # 配置文件
├── core/              # 核心审计逻辑
│   ├── analyzers/     # 各种分析器
│   ├── parsers/       # 代码解析器
│   └── ai/           # AI分析模块
└── docker/           # Docker配置文件
```

## 技术架构

### 后端组件
- FastAPI: Web框架
- ChromaDB: 向量数据库
- LangChain: AI链式调用
- OpenAI/DeepSeek: 大语言模型

### 前端技术
- Bootstrap 5.1.3
- Vue.js (可选)

### 核心功能实现
- 向量数据库集成
  - 使用 ChromaDB 存储代码向量
  - 支持语义相似度搜索
  - 实现代码上下文关联

- AI 分析流程
  - 静态代码扫描
  - 向量数据库导入
  - AI 验证分析
  - 漏洞关联分析
  - 修复建议生成

## 环境变量说明
```env
# 必需配置
OPENAI_API_KEY=your_api_key_here
OPENAI_API_BASE=your_api_base_url
OPENAI_MODEL=your_preferred_model

# 可选配置
LOG_LEVEL=INFO              # 日志级别：DEBUG/INFO/WARNING/ERROR
CORS_ORIGINS=["*"]          # CORS 配置
VECTOR_STORE_DIR=vector_db  # 向量数据库存储目录
UPLOAD_DIR=uploads          # 文件上传目录
LOG_DIR=logs               # 日志目录
```

## 开发指南

### 本地开发
1. 安装开发依赖
```bash
pip install -e ".[dev]"
```

2. 代码格式化
```bash
black .
isort .
```

3. 类型检查
```bash
mypy .
```

4. 运行测试
```bash
pytest
```

### 目录说明
- `backend/static/`: 存放前端静态文件
- `core/analyzers/`: 核心分析器实现
- `core/parsers/`: 各语言解析器
- `core/ai/`: AI 模型集成

### API 文档
启动服务后访问：http://127.0.0.1:8000/docs

## 联系方式

如有问题或建议，请通过 Issue 与我联系。
