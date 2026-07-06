# PhishGuard 钓鱼邮件检测智能体

企业内部钓鱼邮件检测工具，支持 `.msg` / `.eml` 文件上传分析。  
多维分析 + 综合评分 + 大白话报告，帮安全运营和普通员工快速识别钓鱼风险。

---

## 功能特性

### 核心能力

| 维度 | 检测内容 | 数据源 |
|------|----------|--------|
| 🔗 **链接分析** | 短链接还原、跳转链追踪、域名仿冒检测（品牌 typosquatting）、免费托管平台识别、域名 WHOIS 年龄、链接显示文本与真实地址一致性 | 内置规则 + VirusTotal |
| 📎 **附件分析** | 文件类型伪装检测、OLE 宏分析、密码保护压缩包识别、危险扩展名/高危类型分级 | 内置规则 + oletools + VirusTotal |
| 📝 **内容分析** | 社会工程学话术识别、冒充/凭证窃取/欺骗意图评分、攻击类型分类、OAuth 授权劫持检测 | LLM（规则引擎兜底） |
| 👤 **发件人分析** | 显示名与邮箱一致性、SPF/DKIM/DMARC 认证、域名仿冒（内部域编辑距离检测）、Reply-To/Return-Path 异常 | 邮件头解析 + WHOIS |
| 🏗️ **HTML 结构** | 假登录框识别、表单/跟踪像素/隐藏元素、JS 数据外传检测、反分析对抗代码、Base64 隐藏 URL | BeatifulSoup 规则分析 |

### 特色功能

- **综合评分引擎** — 四维度加权 + 跨维度关联加分 + HTML 结构附加分，分数范围 0-100
- **三层报告** — ① 一眼结论 + ② 大白话问题清单 + ③ 技术细节（可折叠），支持打印/导出 PDF
- **LLM 驱动** — 内容深度分析 + findings 批量大白话翻译；LLM 不可用时自动降级到规则引擎
- **VirusTotal 集成** — URL 和附件的多引擎查杀结果
- **内置缓存** — 同一邮件先 analyze 再 report 只跑一次完整流水线
- **校准工具** — 用已知样本跑混淆矩阵 + 阈值网格扫描，选最优切点

## 快速开始

### 环境要求

- Python ≥ 3.10
- （可选）兼容 OpenAI API 的 LLM 服务（如 Qwen、DeepSeek、GPT）
- （可选）VirusTotal API Key

### 安装

```bash
# 克隆仓库
git clone https://github.com/1156494497/phish-detector.git
cd phish-detector

# 安装依赖
pip install -r requirements.txt
```

### 配置

编辑 `config.py` 或通过环境变量配置：

```bash
# LLM 配置（可选，不配置则使用规则引擎兜底）
export LLM_BASE_URL="http://your-llm-server:7000/v1"
export LLM_API_KEY="your-api-key"
export LLM_MODEL="Qwen3.6-35B-A3B"

# VirusTotal 配置（可选）
export VT_API_KEY="your-vt-api-key"

# 服务配置
export HOST="0.0.0.0"
export PORT=8899
```

### 启动

```bash
python app.py
```

服务启动后访问 `http://localhost:8899` 即可上传邮件文件进行分析。

### API 接口

| 接口 | 方法 | 说明 |
|------|------|------|
| `/` | GET | 前端上传页面 |
| `/api/analyze` | POST | 上传邮件，返回 JSON 检测结果 |
| `/api/report` | POST | 上传邮件，返回 HTML 检测报告（大白话分层版） |
| `/api/health` | GET | 健康检查，返回 LLM/VT/缓存状态 |
| `/api/debug/score-schema` | GET | 返回当前评分阈值与权重的含义说明 |

## 评分体系

```
综合得分 = Σ(维度分 × 权重) + 关联加分 + HTML 附加分
```

| 风险等级 | 分数范围 | 含义 |
|----------|----------|------|
| 🟢 安全 | 0 – 30 | 普通邮件，无需处置 |
| 🟡 可疑 | 31 – 60 | 建议人工复核 |
| 🔴 高危 | 61 – 100 | 极可能为钓鱼邮件 |

### 权重配置

| 维度 | 默认权重 | 说明 |
|------|----------|------|
| 链接风险 | 30% | 钓鱼邮件中 90%+ 含恶意链接 |
| 附件风险 | 25% | 含恶意附件时危害极大 |
| 内容风险 | 30% | 话术欺骗性是最强信号 |
| 发件人风险 | 15% | 认证失效 ≠ 钓鱼，权重不宜过高 |

所有阈值和权重均可通过 `config.py` 按需调整。

## 校准工具

用已知样本优化评分阈值：

```bash
# 准备样本
mkdir -p samples/phishing  samples/benign
# 把已知钓鱼邮件放入 samples/phishing/
# 把已知正常邮件放入 samples/benign/

# 运行校准
python calibrate.py
```

输出内容：
- 每封邮件的得分与系统判定
- 混淆矩阵 + 准确率/召回率/F1
- 阈值网格扫描结果，推荐最优切点

## 项目结构

```
phish-detector/
├── app.py                  # FastAPI 主入口
├── config.py               # 配置文件（阈值、权重、API 密钥）
├── models.py               # 数据模型（Pydantic）
├── scoring.py              # 综合评分引擎
├── cache.py                # LRU 结果缓存
├── report_generator.py     # HTML 报告生成器
├── terminology.py          # findings 大白话翻译
├── calibrate.py            # 评分阈值校准工具
├── requirements.txt        # Python 依赖
├── analyzers/
│   ├── __init__.py
│   ├── eml_parser.py       # .eml 文件解析器
│   ├── msg_parser.py       # .msg 文件解析器
│   ├── url_analyzer.py     # URL 分析模块
│   ├── attachment_analyzer.py  # 附件分析模块
│   ├── content_analyzer.py # 内容分析模块（LLM + 规则引擎）
│   └── vt_checker.py       # VirusTotal 查询模块
├── rules/
│   └── suspicious_keywords.json  # 可疑关键词规则
├── samples/
│   └── README.md           # 样本目录说明
├── static/
│   └── index.html          # 前端上传页面
└── start_service.bat       # Windows 启动脚本
```

## 技术栈

- **框架**: FastAPI + uvicorn
- **LLM**: OpenAI 兼容 API（Qwen / DeepSeek / GPT）
- **安全检测**: oletools（VBA 宏分析）、python-whois（域名 WHOIS）
- **威胁情报**: VirusTotal API v3
- **前端**: 纯静态 HTML（无框架依赖）

## 注意事项

1. LLM 和 VirusTotal 均为可选功能 — 不配置时规则引擎 + 内置规则仍可运行
2. 上传文件大小上限默认 50MB，可在 `config.py` 中调整
3. 报告仅供辅助判断，不能完全代替人工分析
4. 校准工具会真实调用 LLM 和 VT，样本较多时请留意 API 配额

## License

MIT
