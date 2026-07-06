"""
钓鱼邮件检测智能体 - 数据模型
"""
from pydantic import BaseModel, Field
from typing import Optional
from enum import Enum


class RiskLevel(str, Enum):
    SAFE = "safe"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


# ============================================================
# MSG 解析结果
# ============================================================
class AttachmentInfo(BaseModel):
    filename: str
    extension: str = ""
    mime_type: str = ""
    size: int = 0
    sha256: str = ""
    data_length: int = 0  # 二进制数据长度，不直接存bytes


class EmailMetadata(BaseModel):
    sender_name: str = ""
    sender_email: str = ""
    sender_domain: str = ""
    to: list[str] = Field(default_factory=list)
    cc: list[str] = Field(default_factory=list)
    subject: str = ""
    date: str = ""
    message_id: str = ""
    headers: str = ""
    has_html: bool = False
    url_count: int = 0
    attachment_count: int = 0


class ParsedEmail(BaseModel):
    metadata: EmailMetadata
    body_text: str = ""
    body_html: str = ""
    urls: list[str] = Field(default_factory=list)
    url_display_map: dict[str, str] = Field(default_factory=dict)  # {url: display_text}
    attachments: list[AttachmentInfo] = Field(default_factory=list)
    # 附件二进制数据单独存储，不走Pydantic序列化
    class Config:
        arbitrary_types_allowed = True


# ============================================================
# URL 分析结果
# ============================================================
class URLDetail(BaseModel):
    url: str
    domain: str = ""
    score: int = 0
    is_short_url: bool = False
    redirect_chain: list[str] = Field(default_factory=list)
    final_domain: str = ""
    domain_age_days: Optional[int] = None
    is_ip_url: bool = False
    is_free_hosting: bool = False
    suspicious_keywords: list[str] = Field(default_factory=list)
    is_https: bool = True
    typosquat_brand: str = ""
    typosquat_kind: str = ""  # 仿冒类型: name_match(主名混淆) / prefix(含品牌前缀) / suffix(含品牌后缀) / subdomain(品牌放子域) / path(含路径)
    # VirusTotal
    vt_checked: bool = False
    vt_malicious_count: int = 0      # VT报毒引擎数
    vt_total_engines: int = 0       # VT总引擎数
    vt_reputation: int = 0           # VT声誉分
    display_text: str = ""           # <a>标签的显示文本
    href_mismatch: bool = False      # 显示文本与href域名不一致
    findings: list[str] = Field(default_factory=list)


class URLAnalysisResult(BaseModel):
    urls_analyzed: list[URLDetail] = Field(default_factory=list)
    max_score: int = 0
    findings: list[str] = Field(default_factory=list)


# ============================================================
# 附件分析结果
# ============================================================
class AttachmentDetail(BaseModel):
    filename: str
    extension: str
    score: int = 0
    file_type_danger: str = "unknown"  # high / medium / low
    has_macro: bool = False
    macro_suspicious_keywords: list[str] = Field(default_factory=list)
    is_disguised: bool = False  # 文件类型伪装
    expected_type: str = ""
    actual_type: str = ""
    sha256: str = ""
    size: int = 0
    # VirusTotal
    vt_checked: bool = False
    vt_malicious_count: int = 0
    vt_total_engines: int = 0
    vt_link: str = ""               # VT报告链接
    is_encrypted: bool = False      # 密码保护压缩包
    inner_files: list[str] = Field(default_factory=list)  # 压缩包内文件列表
    findings: list[str] = Field(default_factory=list)


class AttachmentAnalysisResult(BaseModel):
    attachments_analyzed: list[AttachmentDetail] = Field(default_factory=list)
    max_score: int = 0
    findings: list[str] = Field(default_factory=list)


# ============================================================
# 内容分析结果
# ============================================================
class AttackType(str, Enum):
    """
    攻击类型枚举，与 phishing-email-analyzer SKILL 对齐。
    所有 LLM 返回的 attack_type 必须映射到以下枚举值之一。
    """
    CREDENTIAL_PHISHING = "credential_phishing"       # 凭据窃取（假登录页）
    CREDENTIAL_THEFT_HTML = "credential_theft_html"   # HTML附件凭据窃取
    CEO_FRAUD_BEC = "ceo_fraud_bec"                  # CEO欺诈/BEC
    MALICIOUS_ATTACHMENT = "malicious_attachment"     # 恶意附件
    MALICIOUS_LINK = "malicious_link"                 # 恶意链接
    SOCIAL_ENGINEERING = "social_engineering"         # 社工钓鱼
    SPEAR_PHISHING = "spear_phishing"                 # 鱼叉式定向攻击
    CLONE_PHISHING = "clone_phishing"                 # 克隆钓鱼（复制合法邮件替换链接/附件）
    PAYMENT_REDIRECT = "payment_redirect"             # 支付重定向
    OAUTH_HIJACK = "oauth_hijack"                    # OAuth授权劫持
    FINANCIAL_FRAUD = "financial_fraud"               # 财务诈骗（LLM 旧返回值，兼容）
    MALWARE_DELIVERY = "malware_delivery"             # 恶意软件投递（LLM 旧返回值，兼容）
    INTERNAL_IMPERSONATION = "internal_impersonation" # 内部冒充（LLM 旧返回值，兼容）
    LOTTERY_SCAM = "lottery_scam"                    # 中奖诈骗（LLM 旧返回值，兼容）
    UNKNOWN = "unknown"                              # 未知

    @staticmethod
    def from_str(value: str) -> "AttackType":
        """将 LLM 自由字符串映射为枚举，兜底返回 UNKNOWN。"""
        if not value:
            return AttackType.UNKNOWN
        v = value.lower().strip()
        # 精确映射
        mapping = {
            "credential_phishing": AttackType.CREDENTIAL_PHISHING,
            "credential_theft_html": AttackType.CREDENTIAL_THEFT_HTML,
            "ceo_fraud_bec": AttackType.CEO_FRAUD_BEC,
            "bec": AttackType.CEO_FRAUD_BEC,
            "malicious_attachment": AttackType.MALICIOUS_ATTACHMENT,
            "malicious_link": AttackType.MALICIOUS_LINK,
            "social_engineering": AttackType.SOCIAL_ENGINEERING,
            "spear_phishing": AttackType.SPEAR_PHISHING,
            "clone_phishing": AttackType.CLONE_PHISHING,
            "payment_redirect": AttackType.PAYMENT_REDIRECT,
            "oauth_hijack": AttackType.OAUTH_HIJACK,
            "oauth_hijacking": AttackType.OAUTH_HIJACK,
            # LLM 旧返回值兼容
            "financial_fraud": AttackType.FINANCIAL_FRAUD,
            "malware_delivery": AttackType.MALWARE_DELIVERY,
            "internal_impersonation": AttackType.INTERNAL_IMPERSONATION,
            "lottery_scam": AttackType.LOTTERY_SCAM,
            "other": AttackType.UNKNOWN,
        }
        return mapping.get(v, AttackType.UNKNOWN)

    @staticmethod
    def to_display_name(attack_type: "AttackType") -> str:
        """攻击类型的中文显示名。"""
        return {
            AttackType.CREDENTIAL_PHISHING: "凭据钓鱼（假登录页）",
            AttackType.CREDENTIAL_THEFT_HTML: "HTML附件凭据窃取",
            AttackType.CEO_FRAUD_BEC: "CEO欺诈/BEC",
            AttackType.MALICIOUS_ATTACHMENT: "恶意附件",
            AttackType.MALICIOUS_LINK: "恶意链接",
            AttackType.SOCIAL_ENGINEERING: "社工钓鱼",
            AttackType.SPEAR_PHISHING: "鱼叉式定向攻击",
            AttackType.CLONE_PHISHING: "克隆钓鱼",
            AttackType.PAYMENT_REDIRECT: "支付重定向",
            AttackType.OAUTH_HIJACK: "OAuth授权劫持",
            AttackType.FINANCIAL_FRAUD: "财务诈骗",
            AttackType.MALWARE_DELIVERY: "恶意软件投递",
            AttackType.INTERNAL_IMPERSONATION: "内部冒充",
            AttackType.LOTTERY_SCAM: "中奖诈骗",
            AttackType.UNKNOWN: "未知",
        }.get(attack_type, "未知")


class ContentAnalysisResult(BaseModel):
    social_engineering: int = 0       # 社会工程学风险 0-100
    impersonation: int = 0            # 冒充风险 0-100
    credential_harvesting: int = 0    # 凭证窃取风险 0-100
    deception_intent: int = 0         # 欺骗意图 0-100
    summary: str = ""                 # 分析结论
    suspicious_indicators: list[str] = Field(default_factory=list)
    used_llm: bool = False           # 是否使用了LLM（否则是规则引擎）
    score: int = 0                   # 综合内容得分
    # LLM 扩展字段（attack_type 已升级为枚举，存储枚举值字符串）
    attack_type: str = ""             # AttackType 枚举值字符串
    attack_type_display: str = ""     # 中文显示名，由 analyze 阶段填充
    confidence: str = ""              # LLM 判断置信度：high / medium / low
    top_risks: list[dict] = Field(default_factory=list)  # [{"text": str, "severity": "high|medium|low"}, ...]
    # OAuth 劫持检测结果（LLM 分析后由 analyze() 补充）
    oauth_hijack_detected: bool = False
    oauth_hijack_domain: str = ""


# ============================================================
# HTML 结构分析结果
# ============================================================
class HtmlAnalysisResult(BaseModel):
    has_form: bool = False
    form_actions: list[str] = Field(default_factory=list)
    form_input_fields: list[str] = Field(default_factory=list)  # password, email 等输入字段
    has_tracking_pixel: bool = False
    tracking_pixel_urls: list[str] = Field(default_factory=list)
    hidden_text_count: int = 0  # display:none/visibility:hidden 元素数
    # ── 新增：假登录框检测 ──────────────────────────────
    has_fake_login_page: bool = False  # 是否包含假登录框（凭据窃取陷阱）
    fake_login_brand: str = ""         # 仿冒的品牌名 (google/microsoft/adobe/other)
    # ── 新增：深度 JS 分析 ─────────────────────────────
    has_external_data_exfil: bool = False  # 是否向外部地址发送数据
    has_hidden_base64_url: bool = False    # 是否有 base64 编码的隐藏 URL
    has_anti_analysis: bool = False       # 是否有反分析对抗代码（F12/右键禁用）
    has_anti_bot: bool = False          # 是否有反机器人检测
    exfil_domains: list[str] = Field(default_factory=list)   # 数据外传目标域名列表
    hidden_urls: list[str] = Field(default_factory=list)     # 发现的隐藏 URL
    findings: list[str] = Field(default_factory=list)


# ============================================================
# 发件人分析结果
# ============================================================
class SenderAnalysisResult(BaseModel):
    score: int = 0
    display_name_mismatch: bool = False
    suspicious_tld: bool = False
    free_email_provider: bool = False
    domain_age_days: Optional[int] = None
    # 邮件认证 (SPF/DKIM/DMARC)
    spf_result: str = "unknown"      # pass / fail / softfail / none / unknown
    dkim_result: str = "unknown"
    dmarc_result: str = "unknown"
    reply_to_mismatch: bool = False  # Reply-To 与 From 不一致
    return_path_mismatch: bool = False  # Return-Path 与 From 不一致
    findings: list[str] = Field(default_factory=list)


# ============================================================
# 综合评分结果
# ============================================================
class DimensionScore(BaseModel):
    name: str
    weight: float
    score: int
    raw_score: int = 0    # 加权前的原始分（用于报告瀑布展示）
    findings: list[str] = Field(default_factory=list)


class ScoreBreakdown(BaseModel):
    """得分瀑布详情：展示每个步骤的 delta 分值，用于报告/前端的可解释性展示"""
    url_score: int = 0       # URL 维度加权前原始分
    attachment_score: int = 0
    content_score: int = 0
    sender_score: int = 0
    url_contribution: int = 0   # 加权后贡献分（score × weight）
    attachment_contribution: int = 0
    content_contribution: int = 0
    sender_contribution: int = 0
    dim_amp_applied: dict[str, float] = Field(default_factory=dict)  # 各维度放大系数
    correlation_bonus_detail: str = ""  # 关联加分原因说明


class DetectionResult(BaseModel):
    total_score: int = 0
    risk_level: RiskLevel = RiskLevel.SAFE
    dimensions: list[DimensionScore] = Field(default_factory=list)
    score_breakdown: ScoreBreakdown = Field(default_factory=ScoreBreakdown)
    email_metadata: Optional[EmailMetadata] = None
    url_analysis: Optional[URLAnalysisResult] = None
    attachment_analysis: Optional[AttachmentAnalysisResult] = None
    content_analysis: Optional[ContentAnalysisResult] = None
    sender_analysis: Optional[SenderAnalysisResult] = None
    html_analysis: Optional[HtmlAnalysisResult] = None
    correlation_bonus: int = 0  # 跨维度关联加分
    recommendation: str = ""
