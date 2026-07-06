"""
钓鱼邮件检测智能体 - 配置文件
"""
import os

# ============================================================
# LLM 配置
# ============================================================
LLM_BASE_URL = os.getenv("LLM_BASE_URL", "http://192.168.1.1:7000/v1")
LLM_API_KEY = os.getenv("LLM_API_KEY", "password")
LLM_MODEL = os.getenv("LLM_MODEL", "Qwen3.6-35B-A3B")
LLM_TIMEOUT = int(os.getenv("LLM_TIMEOUT", "60"))
LLM_TEMPERATURE = 0.1
LLM_MAX_TOKENS = 4096  # 推理模型需要更多 token 来完成推理链 + 输出内容

# ============================================================
# 评分阈值
# 触发条件 → 业务影响（调整前请先跑 calibrate.py 看混淆矩阵）
# ============================================================
SCORE_SAFE_MAX = 30        # 0-30 安全；综合得分落在此区间 → 普通邮件，无需处置
SCORE_SUSPICIOUS_MAX = 60  # 31-60 可疑；综合得分在此区间 → 建议人工复核，可下载报告留存
# 61-100 高危；综合得分在此区间 → 极可能为钓鱼邮件，强烈建议不要点击/打开任何内容

# ============================================================
# 评分权重（各维度对最终分的贡献比例，四项之和应为 1.0）
# 权重调整建议：钓鱼邮件中链接+内容最常见 → 给较高权重；发件人欺骗性不一定高
# ============================================================
WEIGHT_URL = 0.30         # 链接风险权重 30%；钓鱼邮件中 90%+ 含恶意链接
WEIGHT_ATTACHMENT = 0.25   # 附件风险权重 25%；含恶意附件（宏/PDF exploit）时危害极大
WEIGHT_CONTENT = 0.30      # 内容风险权重 30%；话术欺骗性（紧迫/冒充/财税话术）是最强信号
WEIGHT_SENDER = 0.15       # 发件人风险权重 15%；SPF/DKIM 失效 ≠ 钓鱼，权重不宜过高

# 各维度最终得分的放大系数（用于整体调档，>1 放大风险倾向，<1 收紧）
# 调整方式：校准后发现某维度系统性偏低/偏高时改这里即可，不必改业务代码
# 示例：若品牌仿冒邮件中 URL 维度系统性偏低 → 提高 DIM_AMP_URL 至 1.2
DIM_AMP_URL = 1.0
DIM_AMP_ATTACHMENT = 1.0
DIM_AMP_CONTENT = 1.0
DIM_AMP_SENDER = 1.0

# ============================================================
# 发件人维度各项加分（之前散落在 scoring.py 里的"魔法数字"）
# 改这里即可调档，不必改业务代码
# ============================================================
SENDER_SCORE_BRAND_MISMATCH = 80   # 显示名含品牌关键词但域名不匹配 → 典型冒充，几乎确定恶意
SENDER_SCORE_NAME_EMAIL_MISMATCH = 20  # 显示名与邮箱本地 token 重合率 < 30% → 不一致警告
SENDER_SCORE_FREE_PROVIDER = 15   # 发件人使用免费邮箱（gmail/qq/163）→ 配合其他信号时加分
SENDER_SCORE_SUSPICIOUS_TLD = 40  # 发件人域名使用 .tk/.ml/.xyz 等可疑顶级域 → 高风险
SENDER_SCORE_INTERNAL_TYPOSQUAT = 60   # 域名仿冒内部域名（编辑距离 ≤ 3 或主名前缀）→ 内部钓鱼极高风险
SENDER_SCORE_INTERNAL_NAME_CONTAIN = 50  # 发件域名包含内部域名关键词（如 mycompany-security.com）→ 品牌仿冒
SENDER_SCORE_EMPTY_SENDER = 60    # 发件人地址为空 → 伪造发件人，极高风险
SENDER_SCORE_SPF_FAIL = 40       # SPF 验证失败 → 发件服务器未授权，但未必恶意
SENDER_SCORE_SPF_SOFTFAIL = 20  # SPF 软失败 → 轻微可疑
SENDER_SCORE_SPF_NONE = 10       # SPF 未配置 → 不确定，不应直接判恶意
SENDER_SCORE_DKIM_FAIL = 40     # DKIM 签名验证失败 → 邮件可能被篡改
SENDER_SCORE_DKIM_NONE = 5       # DKIM 未配置 → 不确定
SENDER_SCORE_DMARC_FAIL = 30     # DMARC 验证失败 → 域名对齐失败，高度可疑
SENDER_SCORE_DMARC_NONE = 5      # DMARC 未配置 → 不确定
SENDER_SCORE_REPLYTO_MISMATCH = 35  # Reply-To 域与 From 域不一致 → 回复会发到另一地址，极可疑
SENDER_SCORE_RETURNPATH_MISMATCH = 25  # Return-Path 域与 From 域不一致 → 退信地址异常

# ============================================================
# 跨维度关联加分参数
# 钓鱼邮件通常多个维度同时异常，关联命中比单一维度更可信
# ============================================================
CORR_HIGH_THRESHOLD = 60      # 维度分数高于此视为"高分"
CORR_MEDIUM_THRESHOLD = 30    # 维度分数高于此视为"中等"
CORR_BONUS_3HIGH = 15        # 3+ 维度同时高分 → 组合攻击特征，可能性极高
CORR_BONUS_2HIGH = 8         # 2 维度同时高分 → 组合攻击特征
CORR_BONUS_ALL_MEDIUM = 5     # 4 维度全部中等以上 → 全面可疑
CORR_BONUS_PATTERN = 10       # 命中特定关联模式（品牌+发件人不一致+链接 或 凭证+紧迫+链接）
CORR_BONUS_MAX = 25           # 关联加分上限，避免分数溢出 100

# HTML 结构加分参数（表单/追踪像素/隐藏元素等）
HTML_BONUS_PER_FINDING = 10   # 每发现一个 HTML 结构问题（如表单）→ +10
HTML_BONUS_MAX = 30           # HTML 结构附加分上限

# ============================================================
# 文件类型危险等级
# ============================================================
DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js",
    ".wsf", ".hta", ".msi", ".dll", ".com", ".pif", ".cpl",
    ".reg", ".inf", ".lnk",
    ".iso", ".img", ".vhd", ".vhdx",  # 现代载荷容器
}
MEDIUM_RISK_EXTENSIONS = {
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".pdf", ".rtf", ".xlsm", ".docm", ".pptm",
    ".zip", ".rar", ".7z",  # 压缩包常见用于传递恶意载荷，需检查内部文件
    ".html",  # HTML附件可能包含钓鱼表单
}
SAFE_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".svg",
    ".txt", ".csv", ".json", ".xml",
    ".mp3", ".mp4", ".wav", ".avi", ".mov",
}

# ============================================================
# URL 分析
# ============================================================
SHORT_URL_SERVICES = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "rebrand.ly", "bl.ink", "short.io",
    "surl.li", "cutt.ly", "v.gd", "tiny.cc", "lnkd.in",
}

FREE_HOSTING_PLATFORMS = {
    "github.io", "gitlab.io", "netlify.app", "vercel.app",
    "herokuapp.com", "azurewebsites.net", "firebaseapp.com",
    "web.app", "surge.sh", "render.com", "fly.dev",
    "pages.dev", "workers.dev", "notion.site",
}

SUSPICIOUS_URL_KEYWORDS = [
    "login", "verify", "secure", "account", "password",
    "signin", "sign-in", "update", "confirm", "authenticate",
    "credential", "banking", "wallet", "paypal", "microsoft",
    "google", "apple", "amazon", "netflix", "dropbox",
    "suspended", "limited", "restricted", "locked",
]

# 常见企业品牌域名（用于仿冒检测）
# 结构: brand_key -> {"region": "cn"|"global", "main_names": [品牌常用主名...], "official_domains": [官方域名...]}
COMMON_BRANDS = {
    # ── 海外品牌 ──
    "microsoft": {
        "region": "global",
        "main_names": ["microsoft", "ms"],
        "official_domains": ["microsoft.com", "office.com", "live.com", "outlook.com", "azure.com"],
    },
    "google": {
        "region": "global",
        "main_names": ["google", "goog"],
        "official_domains": ["google.com", "gmail.com", "googlemail.com"],
    },
    "apple": {
        "region": "global",
        "main_names": ["apple", "icloud"],
        "official_domains": ["apple.com", "icloud.com", "me.com"],
    },
    "amazon": {
        "region": "global",
        "main_names": ["amazon", "aws"],
        "official_domains": ["amazon.com", "aws.amazon.com"],
    },
    "paypal": {
        "region": "global",
        "main_names": ["paypal"],
        "official_domains": ["paypal.com"],
    },
    "netflix": {
        "region": "global",
        "main_names": ["netflix"],
        "official_domains": ["netflix.com"],
    },
    "dropbox": {
        "region": "global",
        "main_names": ["dropbox"],
        "official_domains": ["dropbox.com"],
    },
    "linkedin": {
        "region": "global",
        "main_names": ["linkedin"],
        "official_domains": ["linkedin.com"],
    },
    "facebook": {
        "region": "global",
        "main_names": ["facebook", "meta", "instagram"],
        "official_domains": ["facebook.com", "meta.com", "instagram.com"],
    },
    "twitter": {
        "region": "global",
        "main_names": ["twitter", "x"],
        "official_domains": ["twitter.com", "x.com"],
    },
    "adobe": {
        "region": "global",
        "main_names": ["adobe"],
        "official_domains": ["adobe.com"],
    },
    "salesforce": {
        "region": "global",
        "main_names": ["salesforce", "sf"],
        "official_domains": ["salesforce.com"],
    },
    "zoom": {
        "region": "global",
        "main_names": ["zoom"],
        "official_domains": ["zoom.us", "zoom.com"],
    },
    "slack": {
        "region": "global",
        "main_names": ["slack"],
        "official_domains": ["slack.com"],
    },
    "dhl": {
        "region": "global",
        "main_names": ["dhl"],
        "official_domains": ["dhl.com"],
    },
    "fedex": {
        "region": "global",
        "main_names": ["fedex"],
        "official_domains": ["fedex.com"],
    },
    "ups": {
        "region": "global",
        "main_names": ["ups"],
        "official_domains": ["ups.com"],
    },
    "chase": {
        "region": "global",
        "main_names": ["chase", "jpmorgan"],
        "official_domains": ["chase.com"],
    },
    "wellsfargo": {
        "region": "global",
        "main_names": ["wellsfargo", "wells"],
        "official_domains": ["wellsfargo.com"],
    },
    "hsbc": {
        "region": "global",
        "main_names": ["hsbc"],
        "official_domains": ["hsbc.com"],
    },
    # ── 中国品牌 ──
    "tencent": {
        "region": "cn",
        "main_names": ["tencent", "腾讯", "qq", "wechat", "微信"],
        "official_domains": ["tencent.com", "qq.com", "weixin.qq.com", "wechat.com"],
    },
    "alibaba": {
        "region": "cn",
        "main_names": ["alibaba", "阿里巴巴", "aliyun", "阿里云"],
        "official_domains": ["alibaba.com", "taobao.com", "tmall.com", "aliyun.com"],
    },
    "jd": {
        "region": "cn",
        "main_names": ["jd", "jingdong", "京东", "jdfin"],
        "official_domains": ["jd.com", "jd.hk"],
    },
    "baidu": {
        "region": "cn",
        "main_names": ["baidu", "百度"],
        "official_domains": ["baidu.com"],
    },
    "douyin": {
        "region": "cn",
        "main_names": ["douyin", "字节跳动", "bytedance", "tiktok"],
        "official_domains": ["douyin.com", "bytedance.com", "tiktok.com"],
    },
    "meituan": {
        "region": "cn",
        "main_names": ["meituan", "美团"],
        "official_domains": ["meituan.com"],
    },
    "pinduoduo": {
        "region": "cn",
        "main_names": ["pinduoduo", "拼多多", "pdd"],
        "official_domains": ["pinduoduo.com"],
    },
    "icbc": {
        "region": "cn",
        "main_names": ["icbc", "工商银行"],
        "official_domains": ["icbc.com.cn"],
    },
    "ccb": {
        "region": "cn",
        "main_names": ["ccb", "建设银行"],
        "official_domains": ["ccb.com"],
    },
    "boc": {
        "region": "cn",
        "main_names": ["boc", "中国银行"],
        "official_domains": ["boc.cn"],
    },
    "abc": {
        "region": "cn",
        "main_names": ["abc", "农业银行"],
        "official_domains": ["abchina.com"],
    },
    "cmb": {
        "region": "cn",
        "main_names": ["cmb", "招商银行"],
        "official_domains": ["cmbchina.com"],
    },
    "unionpay": {
        "region": "cn",
        "main_names": ["unionpay", "银联", "chinaunionpay"],
        "official_domains": ["unionpay.com", "chinaunionpay.com.cn"],
    },
    "china_tax": {
        "region": "cn",
        "main_names": ["chinatax", "税务局", "税务", "个税"],
        "official_domains": ["chinatax.gov.cn"],
    },
    "railway_12306": {
        "region": "cn",
        "main_names": ["12306", "railway"],
        "official_domains": ["12306.cn"],
    },
    "sf_express": {
        "region": "cn",
        "main_names": ["sf", "顺丰", "sfexpress"],
        "official_domains": ["sf-express.com"],
    },
    "bilibili": {
        "region": "cn",
        "main_names": ["bilibili", "b站", "哔哩哔哩"],
        "official_domains": ["bilibili.com"],
    },
    "xiaomi": {
        "region": "cn",
        "main_names": ["xiaomi", "小米", "mi"],
        "official_domains": ["mi.com", "xiaomi.com"],
    },
    "huawei": {
        "region": "cn",
        "main_names": ["huawei", "华为"],
        "official_domains": ["huawei.com"],
    },
    # ── 金融/税务 ──
    "tax": {
        "region": "cn",
        "main_names": ["个人所得税", "个税", "税务申报", "退税", "补税", "税务", "税务局", "国税", "地稅"],
        "official_domains": [],
    },
    "bank": {
        "region": "cn",
        "main_names": ["银行", "网银", "电子银行", "手机银行", "直销银行"],
        "official_domains": [],
    },
}

# ============================================================
# WHOIS 缓存
# ============================================================
WHOIS_CACHE_TTL = 3600  # 1小时缓存

# ============================================================
# VirusTotal 配置
# ============================================================
VT_API_KEY = os.getenv("VT_API_KEY", "key_1234567890")
VT_BASE_URL = "https://www.virustotal.com/api/v3"
VT_RATE_LIMIT_DELAY = 0  # 禁用限速等待（已购买付费 API 或接受超限风险时可设为 0）
VT_TIMEOUT = 15
VT_CACHE_TTL = 86400  # 查询结果缓存24小时

# ============================================================
# 服务配置
# ============================================================
HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", "8899"))
MAX_UPLOAD_SIZE = 50 * 1024 * 1024  # 50MB
