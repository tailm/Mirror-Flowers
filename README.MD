# Mirror Flowers (镜花)

![image-20250205181045094](https://raw.githubusercontent.com/Ky0toFu/Mirror-Flowers/refs/heads/main/Mirror%20Flowers.png)

MirrorFlower(镜花)是一款基于 AI 的代码安全审计工具，支持多种编程语言的代码分析，可以帮助开发者快速发现代码中的潜在安全漏洞。支持DeepSeek-R1，ChatGPT-4o等多种大模型。

## 支持的API接口

FREEGPTAPI：https://github.com/popjane/free_chatgpt_api

SiliconFlow(硅基流动)：https://cloud.siliconflow.cn/i/JzMCyiJ3

如需要使用GPT大模型则使用FREEGPTAPI，使用DeepSeek-R1大模型则使用SiliconFlow API。

SiliconFlow(硅基流动)注册可免费领取14元使用额度，可通过SMS接码平台注册账号，理论可无限免费使用API KEY。

## 核心功能

### 多语言支持
- PHP
- Java
- Python
- JavaScript

### 依赖分析
- Maven (pom.xml)
- NPM (package.json)
- Python (requirements.txt)
- Composer (composer.json)

### 框架安全分析
- Spring Framework
  - Spring Security配置审计
  - 权限控制检查
  - CSRF/XSS防护
  - 跨域配置检查

- Django
  - 中间件配置检查
  - CSRF Token验证
  - XSS防护配置
  - 调试模式检查

- Express.js
  - 安全中间件配置
  - 认证机制检查
  - CORS配置审计
  - 输入验证检查

- Hibernate
  - HQL注入检测
  - 缓存配置审计
  - 实体验证检查
  - 会话管理检查

### 安全检查特性

#### PHP安全检查
- 文件包含漏洞（include/require）
- SQL注入（mysql_*函数）
- 命令注入（system, exec, shell_exec）
- 文件上传漏洞
- 反序列化漏洞（unserialize）
- XSS（echo, print）
- SSRF漏洞
- 目录遍历
- 会话管理问题
- 配置文件泄露

#### Java安全检查
- SQL注入（PreparedStatement相关）
- 命令注入（Runtime.exec, ProcessBuilder）
- XXE漏洞（XML解析器配置）
- 反序列化漏洞（readObject）
- 不安全的文件操作
- CSRF/XSS防护
- 权限控制缺陷
- 线程安全问题
- 密码学实现缺陷
- 日志信息泄露

#### Python安全检查
- 不安全的反序列化（pickle.loads, yaml.load）
- 命令注入（os.system, eval, exec, subprocess）
- 不安全的模块导入（__import__）
- SQL注入（字符串格式化, execute）
- 路径遍历（open, os.path）
- 模板注入（render_template_string）
- 密码学实现问题（weak random）
- 环境变量泄露
- 调试配置泄露
- 不安全的依赖加载

#### JavaScript安全检查
- XSS（DOM型和反射型）
- 原型污染
- 不安全的第三方依赖
- 客户端存储安全
- 不安全的随机数生成
- CSRF防护缺失
- 跨域配置问题
- 敏感信息泄露
- 不安全的正则表达式
- 事件监听器泄露

### 分析器组件
- TaintAnalyzer: 污点分析和数据流追踪
- SecurityAnalyzer: 通用安全问题检测
- DependencyAnalyzer: 依赖组件安全分析
- FrameworkAnalyzer: 框架特定安全检查
- ConfigAnalyzer: 配置文件安全分析
- ContextAnalyzer: 上下文感知分析

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

2. 安装依赖
```bash
pip install -r requirements.txt
```

3. 配置环境变量
```env
OPENAI_API_KEY=your_api_key_here
OPENAI_API_BASE=your_api_base_url
OPENAI_MODEL=your_preferred_model
```

4. 启动服务
```bash
uvicorn backend.app:app --reload
```

## 注意事项

1. 文件大小限制：10MB
2. 支持的文件类型：.php, .java, .py, .js
3. API密钥安全：请妥善保管API密钥
4. 分析时间：大型项目可能需要较长时间
5. 结果验证：建议结合人工审查
6. API配置问题：如果提示"API配置更新错误"或"不存在某个模型"，请检查API Base URL格式，尝试在URL后添加/v1或删除/v1（例如：https://api.example.com 或 https://api.example.com/v1）

## 许可证

MIT License

## 联系方式

如有问题或建议，请通过 Issue 与我联系。
