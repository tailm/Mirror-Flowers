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


## 更新记录
### 2025-02-17
- 修复了API配置保存和调用的问题
- 修复了AI分析结果在前端显示的问题
- 优化了JSON响应格式，确保前端能正确解析和显示AI分析建议


### 2025-02-14
- 优化了依赖管理：
  - 更新了 setup.py 配置
  - 重构了 requirements.txt
  - 添加了开发依赖选项
- 改进了前端显示：
  - 优化了 AI 分析建议的展示
  - 添加了更详细的漏洞分析信息
  - 改进了深色模式支持
- 文档更新：
  - 完善了安装说明
  - 添加了详细的使用说明
  - 更新了 API 配置说明
- 核心功能增强：
  - 实现了基于向量数据库的代码分析
  - 支持将所有源码导入本地向量库
  - 新增指定方法获取潜在漏洞入口点
  - 实现 AI 与向量库关联分析功能
  - 优化了代码上下文理解能力
  - 提高了漏洞分析的准确性

### 2025-02-11
- 完善了Python代码分析功能：
  - 添加了完整的依赖分析，支持追踪导入关系和别名
  - 增强了函数调用分析，支持类方法和实例方法的调用追踪
  - 添加了变量使用分析，支持追踪全局变量和实例变量
  - 改进了类继承分析，支持多级继承路径分析
- 优化了分析器架构：
  - 使用访问者模式重构了代码分析逻辑
  - 添加了类型提示和详细文档
  - 改进了错误处理机制

## 支持的API接口

FREEGPTAPI：https://github.com/popjane/free_chatgpt_api

SiliconFlow(硅基流动)：https://cloud.siliconflow.cn/i/JzMCyiJ3

如需要使用GPT大模型则使用FREEGPTAPI，使用DeepSeek-R1大模型则使用SiliconFlow API。

SiliconFlow(硅基流动)注册可免费领取14元使用额度，可通过SMS接码平台注册账号，理论可无限免费使用API KEY。

### API 配置说明

配置文件位置: `config/api_config.json`



```json

{

    "api_key": "your_api_key",

    "api_base": "your_api_base_url",

    "model": "your_preferred_model"

}

```


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

### 向量数据库分析
- 代码向量化：
  - 支持多种编程语言的代码向量化
  - 保留代码语义和结构信息
  - 高效的本地向量存储

- 漏洞入口分析：
  - 智能识别潜在漏洞入口点
  - 基于上下文的代码关联分析
  - 支持跨文件依赖追踪

- AI 关联分析：
  - 与向量库深度集成
  - 基于相似度的代码片段匹配
  - 智能关联漏洞模式识别
  - 上下文感知的安全建议

