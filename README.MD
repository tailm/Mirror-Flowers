# Mirror Flowers (镜花)

![image-20250205181045094](https://raw.githubusercontent.com/Ky0toFu/Mirror-Flowers/refs/heads/main/Mirror%20Flowers/Mirror%20Flowers.png)

基于 AI 的代码安全审计工具，支持多种编程语言的代码分析，可以帮助开发者快速发现代码中的潜在安全漏洞。支持DeepSeek-R1，ChatGPT-4o等多种大模型。

## 支持的API接口

FREEGPTAPI：https://github.com/popjane/free_chatgpt_api
SiliconFlow(硅基流动)：https://cloud.siliconflow.cn/i/JzMCyiJ3

如需要使用GPT大模型则使用FREEGPTAPI，使用DeepSeek-R1大模型则使用SiliconFlow API。

SiliconFlow(硅基流动)注册可免费领取14元使用额度，可通过SMS接码平台注册账号，理论可无限免费使用API KEY。

## 功能特点

- 支持单文件和项目文件夹审计
- 支持多种编程语言 (PHP, Java, JavaScript, Python)
- 实时进度显示
- 深度代码分析
- 漏洞详细报告
- 支持亮色/暗色主题切换
- 支持自定义 API 配置

## 支持的文件类型

- PHP (.php)
- Java (.java)
- JavaScript (.js)
- Python (.py)

## 快速开始

### 环境要求

- Python 3.8+
- FastAPI
- Node.js (可选，用于前端开发)

### 安装步骤

1. 克隆项目
```bash
git clone https://github.com/Ky0toFu/Mirror-Flowers.git
cd Mirror Flowers
```

2. 安装依赖
```bash
pip install -r requirements.txt
```

3. 配置环境变量
创建 `.env` 文件并配置以下参数：
```env
OPENAI_API_KEY=your_api_key_here
OPENAI_API_BASE=your_api_base_url
OPENAI_MODEL=your_preferred_model
```

4. 启动服务
```bash
cd backend
uvicorn app:app --reload
```

5. 访问工具
打开浏览器访问 `http://localhost:8000`

## 使用说明

### 单文件审计

1. 在界面上选择"单文件审计"
2. 点击选择文件，上传需要审计的源代码文件
3. 点击"开始审计"按钮
4. 等待分析完成，查看审计结果

### 项目文件夹审计

1. 在界面上选择"项目文件夹审计"
2. 点击选择文件夹，选择需要审计的项目文件夹
3. 系统会自动过滤支持的文件类型
4. 点击"开始审计"按钮
5. 等待分析完成，查看完整的项目审计报告

### 自定义 API 配置

1. 在页面顶部的 API 配置区域输入：
   - OpenAI API Key
   - API Base URL（可选）
   - 选择模型（可选）
2. 点击"更新配置"保存设置

### 主题切换

- 点击右上角的主题切换按钮可以在亮色/暗色主题之间切换
- 主题选择会被保存在本地

## 审计报告说明

审计报告包含以下内容：

1. 漏洞分析
   - 漏洞类型
   - 漏洞位置
   - 严重程度
   - 详细描述
   - 影响范围
   - 修复建议

2. 上下文分析
   - 代码结构分析
   - 数据流分析
   - 相关函数调用

3. 相关文件
   - 受影响的相关文件列表
   - 文件依赖关系

## 注意事项

1. 文件大小限制：项目文件夹总大小不能超过 10MB
2. 支持的文件类型有限，不支持的文件类型会被自动过滤
3. API Key 请妥善保管，不要泄露
4. 分析结果仅供参考，建议结合人工审查

## 常见问题

1. Q: 为什么上传文件后按钮仍然禁用？
   A: 请确保上传的文件类型是支持的文件类型之一。

2. Q: 如何处理大型项目？
   A: 建议分模块上传，每次上传的文件总大小不要超过 10MB。

3. Q: 分析过程中中断了怎么办？
   A: 可以刷新页面重新上传文件进行分析。

## 技术栈

- 后端：Python + FastAPI
- 前端：HTML + JavaScript + Bootstrap
- AI：OpenAI API
- 其他：JSZip, Bootstrap Icons

## 贡献指南

欢迎提交 Issue 和 Pull Request 来帮助改进这个工具。

## 许可证

MIT License

## 联系方式

如有问题或建议，请通过 Issue 与我联系。