"""
内容分析器
使用 LLM 分析邮件内容的欺骗意图，LLM 不可用时降级到关键词规则引擎
"""
from html import unescape
import json
import logging
import os
import re

from openai import OpenAI
from bs4 import BeautifulSoup

from models import ContentAnalysisResult, EmailMetadata, AttackType
from config import (
    LLM_BASE_URL, LLM_API_KEY, LLM_MODEL,
    LLM_TIMEOUT, LLM_TEMPERATURE, LLM_MAX_TOKENS,
)

logger = logging.getLogger(__name__)

# ============================================================
# 关键词规则引擎（LLM 降级方案）
# ============================================================
# 规则结构:
#   - phrases: 短语级匹配列表（精确，含空格/标点的完整套话），比单词更准
#   - keywords: 单词级匹配列表
#   - require_url_proximity: >0 时，该规则只在 URL 附近（n 字符内）命中才加分
#   - weight: 基础权重
#   - description: 中文说明
KEYWORD_RULES = {
    "urgency": {
        "phrases": [
            "click here immediately", "act now", "urgent action required",
            "your account will be suspended", "immediate action needed",
            "24 hours", "48 hours", "限时", "立即处理", "24小时", "48小时",
            "最后机会", "expires in", "will be terminated",
        ],
        "keywords": [
            "紧急", "立即", "马上", "立刻", "尽快", "过期", "限时",
            "immediately", "urgent", "asap", "expire", "limited time",
            "last chance", "hurry", "countdown", "倒计时",
        ],
        "weight": 20,
        "description": "紧迫性话术"
    },
    "threat": {
        "phrases": [
            "account will be locked", "account will be suspended",
            "legal action", "lawsuit", "will be terminated",
            "账户将被冻结", "将被锁定", "法律后果", "追究法律责任",
        ],
        "keywords": [
            "冻结", "封禁", "停用", "关闭", "终止", "违规", "处罚",
            "suspended", "locked", "terminated", "disabled", "blocked",
            "legal", "lawsuit", "penalty", "violation", "fine",
        ],
        "weight": 25,
        "description": "威胁性话术"
    },
    "credential_harvesting": {
        "phrases": [
            "reset your password", "verify your account", "confirm your account",
            "update your information", "sign in to verify", "click here to verify",
            "verify your identity", "enter your password", "input your credentials",
            "重置密码", "验证身份", "确认账户", "更新密码", "输入密码",
            "登录验证", "安全验证", "身份验证",
        ],
        "keywords": [
            "verify your identity", "confirm your account", "update password",
            "reset password", "enter your password", "verify your information",
            "sign in to verify", "authenticate", "账号", "密码",
        ],
        "require_url_proximity": 120,  # 只有 URL 附近出现才算
        "weight": 30,
        "description": "凭证窃取"
    },
    "reward": {
        "phrases": [
            "you have won", "congratulations you won", "you have been selected",
            "click to claim", "领取", "恭喜您获得", "奖金",
            "prize", "lottery winner", "reward", "compensation",
        ],
        "keywords": [
            "中奖", "奖金", "退款", "补偿", "红包", "返利", "领取",
            "恭喜您获得", "您已被选", "幸运用户",
            "won", "prize", "refund", "reward", "lottery",
            "congratulations", "you have been selected", "lucky",
        ],
        "weight": 20,
        "description": "奖励诱导"
    },
    "impersonation": {
        "phrases": [
            "it department", "help desk", "system administrator",
            "security team", "human resources", "财务部", "IT部门",
            "技术支持", "系统管理员", "客服中心",
        ],
        "keywords": [
            "IT部门", "技术支持", "系统管理员", "人力资源部", "财务部",
            "客服中心", "安全团队", "管理员",
            "IT department", "help desk", "system administrator", "HR department",
            "finance department", "customer service", "admin", "support team",
        ],
        "weight": 25,
        "description": "冒充身份"
    },
    "financial_tax": {
        "phrases": [
            "个人所得税", "综合所得", "汇算清缴", "年度汇算",
            "退税", "补税", "专项附加扣除", "逾期申报",
            "tax refund", "tax return", "tax filing", "未申报",
        ],
        "keywords": [
            "个人所得税", "综合所得", "汇算清缴", "退税", "补税",
            "专项附加扣除", "住房租金", "住房贷款利息", "继续教育",
            "赡养老人", "子女教育", "大病医疗", "婴幼儿照护",
            "国家税务总局", "税务局", "税务申报", "税务通知",
            "薪资调整", "工资补发", "补贴发放", "社保", "公积金",
            "年度申报", "逾期申报", "申报截止", "未申报",
            "tax refund", "tax return", "tax filing",
        ],
        "weight": 25,
        "description": "财税钓鱼"
    },
    "oauth_hijack": {
        "phrases": [
            "sign in with google", "sign in with microsoft", "sign in with apple",
            "sign in with facebook", "google authorize", "microsoft authorize",
            "allow access to your account", "authorize this application",
            "用谷歌账号登录", "用微软账号登录", "google登录", "microsoft登录",
        ],
        "keywords": [
            "authorize", "allow access", "connect account", "oauth",
            "access token", "sign in to continue", "continue with google",
            "log in with google", "log in with microsoft", "允许访问", "授权登录",
        ],
        "require_url_proximity": 200,  # OAuth 劫持必须配合链接
        "weight": 30,
        "severity": "critical",
        "description": "OAuth授权劫持"
    },
}


class ContentAnalyzer:
    """分析邮件内容的欺骗意图"""

    def __init__(self):
        self.llm_client = None
        self.llm_available = self._init_llm()

    def _init_llm(self) -> bool:
        """初始化 LLM 客户端"""
        try:
            self.llm_client = OpenAI(
                base_url=LLM_BASE_URL,
                api_key=LLM_API_KEY,
                timeout=LLM_TIMEOUT,
            )
            # 测试连接
            self.llm_client.models.list()
            logger.info(f"LLM 连接成功: {LLM_BASE_URL}")
            return True
        except Exception as e:
            logger.warning(f"LLM 不可用，将使用关键词规则引擎: {e}")
            return False

    def analyze(
        self,
        metadata: EmailMetadata,
        body_text: str,
        body_html: str,
        urls: list[str] = None,
        attachments: list = None,
        html_analysis=None,
    ) -> ContentAnalysisResult:
        """
        分析邮件内容

        Args:
            metadata: 邮件元数据
            body_text: 纯文本正文
            body_html: HTML 正文
            urls: 邮件中的 URL 列表
            attachments: 附件信息列表
            html_analysis: HTML 结构分析结果

        Returns:
            ContentAnalysisResult
        """
        # 提取纯文本内容（优先用 HTML 转文本）
        text_content = self._extract_text_content(body_text, body_html)

        # 截断过长内容（避免超出 LLM token 限制）
        max_chars = 4000
        if len(text_content) > max_chars:
            text_content = text_content[:max_chars] + "\n[内容已截断...]"

        # 尝试 LLM 分析
        if self.llm_available:
            try:
                result = self._analyze_with_llm(metadata, text_content, urls, attachments, html_analysis)
                if result:
                    result.used_llm = True
                    result.score = self._calculate_content_score(result)
                    # OAuth 劫持检测（LLM 分析后补充）
                    oauth_domain = self._detect_oauth_hijack_domain(text_content, urls)
                    if oauth_domain:
                        result.oauth_hijack_detected = True
                        result.oauth_hijack_domain = oauth_domain
                    return result
            except Exception as e:
                logger.warning(f"LLM 分析失败，降级到规则引擎: {e}")

        # 降级到关键词规则引擎
        result = self._analyze_with_rules(metadata, text_content)
        result.used_llm = False
        result.score = self._calculate_content_score(result)
        # OAuth 劫持检测（规则引擎分析后补充）
        oauth_domain = self._detect_oauth_hijack_domain(text_content, urls)
        if oauth_domain:
            result.oauth_hijack_detected = True
            result.oauth_hijack_domain = oauth_domain
        return result

    def _extract_text_content(self, body_text: str, body_html: str) -> str:
        """
        提取邮件正文的纯文本内容，增强处理：
        1. HTML 实体解码（&#x3C; → < 等）
        2. 移除签名块和历史引用（quoted reply）
        3. HTML → 纯文本时去掉 <a> 标签的 URL 文字
        """
        raw_text = body_text or ""

        if body_html:
            try:
                soup = BeautifulSoup(body_html, "html.parser")

                # ① HTML 实体解码（防止 <img src="x" onerror="alert(1)"> 这类绕过）
                for element in soup.find_all(text=True):
                    try:
                        element.string = unescape(element.string or "")
                    except Exception:
                        pass

                # 移除 script/style/img
                for tag in soup(["script", "style", "img"]):
                    tag.decompose()

                # ② 去掉 <a> 标签文字（显示文字里含 URL 会让 LLM 误判）
                for a in soup.find_all("a"):
                    a.replace_with(soup.new_string(a.get("href", "") or ""))

                text = soup.get_text(separator="\n", strip=True)
                raw_text = text
            except Exception as e:
                logger.warning(f"HTML 转文本失败: {e}")

        if not raw_text:
            return ""

        # ③ 移除签名块（标准 Unix sig: "-- \n" 后紧跟的内容）
        lines = raw_text.split("\n")
        sig_cut = len(lines)
        for i, line in enumerate(lines):
            if re.match(r"^--\s*$", line.strip()):
                sig_cut = i
                break
        body_lines = lines[:sig_cut]

        # ④ 移除历史引用行（以 ">" 开头的大量连续行）
        filtered: list[str] = []
        consecutive_gt = 0
        for line in body_lines:
            if re.match(r"^>", line):
                consecutive_gt += 1
                if consecutive_gt > 3:  # 连续 > 3 行认为是引用块，跳过
                    continue
                filtered.append(line)
            else:
                consecutive_gt = 0
                filtered.append(line)

        return "\n".join(filtered).strip()

    def _analyze_with_llm(self, metadata: EmailMetadata, text_content: str, urls=None, attachments=None, html_analysis=None) -> ContentAnalysisResult | None:
        """使用 LLM 分析邮件内容"""
        prompt = self._build_llm_prompt(metadata, text_content, urls, attachments, html_analysis)

        try:
            response = self.llm_client.chat.completions.create(
                model=LLM_MODEL,
                messages=[
                    {"role": "system", "content": "你是企业安全团队的钓鱼邮件分析专家。请严格按照要求返回 JSON 格式的分析结果。"},
                    {"role": "user", "content": prompt},
                ],
                temperature=LLM_TEMPERATURE,
                max_tokens=LLM_MAX_TOKENS,
            )

            content = response.choices[0].message.content
            if not content:
                # 推理模型将分析内容放在 reasoning 字段中，尝试获取
                reasoning = getattr(response.choices[0].message, "reasoning", None)
                if reasoning:
                    content = reasoning
                else:
                    logger.warning("LLM 返回内容为空")
                    return None

            # 去除 markdown 包裹（```json ... ``` 或 ``` ... ```）
            content = content.strip()
            if content.startswith("```"):
                first_newline = content.find("\n")
                if first_newline != -1:
                    content = content[first_newline:]
                content = content.strip().rstrip("`").strip()

            # 去除 markdown 加粗 **text**
            content = re.sub(r'\*\*(.+?)\*\*', r'\1', content)

            # 尝试提取最外层的 JSON 对象
            json_start = content.find("{")
            json_end = content.rfind("}")
            if json_start != -1 and json_end != -1 and json_end > json_start:
                content = content[json_start:json_end + 1]

            # 解析 JSON 结果
            data = json.loads(content)

            # 攻击类型枚举标准化
            raw_attack_type = data.get("attack_type", "")
            attack_enum = AttackType.from_str(raw_attack_type)

            return ContentAnalysisResult(
                social_engineering=int(data.get("social_engineering", 0)),
                impersonation=int(data.get("impersonation", 0)),
                credential_harvesting=int(data.get("credential_harvesting", 0)),
                deception_intent=int(data.get("deception_intent", 0)),
                summary=data.get("summary", ""),
                suspicious_indicators=data.get("suspicious_indicators", []),
                attack_type=attack_enum.value,
                attack_type_display=AttackType.to_display_name(attack_enum),
                confidence=data.get("confidence", ""),
                top_risks=data.get("top_risks", []),
            )

        except json.JSONDecodeError as e:
            logger.warning(f"LLM 返回结果解析失败: {e}")
            return None
        except Exception as e:
            logger.error(f"LLM 调用失败: {e}")
            return None

    def _build_llm_prompt(self, metadata: EmailMetadata, text_content: str, urls=None, attachments=None, html_analysis=None) -> str:
        """构建 LLM 分析 Prompt（注入多维上下文）"""
        # 构建 URL 上下文
        url_context = "无"
        if urls:
            url_lines = []
            for i, url in enumerate(urls[:10], 1):
                # 提取域名
                try:
                    from urllib.parse import urlparse
                    domain = urlparse(url).netloc
                    url_lines.append(f"  {i}. {url} (域名: {domain})")
                except Exception:
                    url_lines.append(f"  {i}. {url}")
            url_context = "\n".join(url_lines)

        # 构建附件上下文
        attachment_context = "无"
        if attachments:
            att_lines = []
            for i, att in enumerate(attachments[:10], 1):
                att_lines.append(f"  {i}. {att.filename} (类型: {att.extension}, 大小: {att.size} bytes)")
            attachment_context = "\n".join(att_lines)

        # 构建 HTML 结构信号上下文
        html_context = "无 HTML 结构风险"
        if html_analysis and html_analysis.findings:
            html_context = "\n".join(f"  - {f}" for f in html_analysis.findings)

        # 发件人域名 vs 收件人域名
        recipient_domain = ""
        if metadata.to:
            for addr in metadata.to:
                if "@" in addr:
                    recipient_domain = addr.split("@")[-1].lower().strip(">")
                    break
        domain_mismatch_note = ""
        if recipient_domain and metadata.sender_domain and metadata.sender_domain != recipient_domain:
            domain_mismatch_note = f"\n⚠️ 发件人域名({metadata.sender_domain})与收件人域名({recipient_domain})不一致"

        return f"""请分析以下邮件内容，判断是否存在钓鱼风险。

从以下维度分析并返回 JSON 格式结果（严格输出有效 JSON，不要 markdown 包裹）：
{{
    "social_engineering": <0-100 社会工程学风险分>,
    "impersonation": <0-100 冒充风险分 — 是否冒充IT部门/HR/银行/税务局/知名机构>,
    "credential_harvesting": <0-100 凭证窃取风险分 — 是否要求输入账号密码或个人信息>,
    "deception_intent": <0-100 欺骗意图分>,
    "attack_type": "<最可能的攻击类型，从以下枚举中选择：credential_phishing(凭据钓鱼)|ceo_fraud_bec(CEO欺诈/BEC)|malicious_attachment(恶意附件)|malicious_link(恶意链接)|social_engineering(社工钓鱼)|spear_phishing(鱼叉式定向攻击)|clone_phishing(克隆钓鱼)|payment_redirect(支付重定向)|oauth_hijack(OAuth授权劫持)|credential_theft_html(HTML附件凭据窃取)|unknown(未知)>",
    "confidence": "<置信度：high|medium|low>",
    "top_risks": [{{"text": "<关键可疑点，≤30字>", "severity": "high|medium|low"}}, ...],
    "summary": "<简要分析结论，中文，≤3句话>",
    "suspicious_indicators": ["<可疑指标1>", "<可疑指标2>", ...]
}}

要求：
- top_risks 最多 5 条，每条 ≤ 30 字
- suspicious_indicators 最多 8 条
- 只输出 JSON，不要任何额外文字

邮件信息：
- 主题: {metadata.subject}
- 发件人: {metadata.sender_name} <{metadata.sender_email}>{domain_mismatch_note}
- 收件人: {', '.join(metadata.to)}
- 日期: {metadata.date}

邮件中的链接：
{url_context}

邮件附件：
{attachment_context}

HTML 结构信号：
{html_context}

邮件正文：
{text_content}
"""

    def _analyze_with_rules(self, metadata: EmailMetadata, text_content: str) -> ContentAnalysisResult:
        """使用增强规则引擎分析：短语匹配 + 密度计算 + URL邻近检测"""
        combined_text = f"{metadata.subject} {text_content}"
        combined_lower = combined_text.lower()
        total_chars = max(len(combined_lower), 1)
        findings = []
        scores = {
            "social_engineering": 0,
            "impersonation": 0,
            "credential_harvesting": 0,
        }

        # URL 邻近判断：在 combined_text 中找到所有 URL 的起止位置
        url_positions: list[tuple[int, int]] = []
        for m in URL_PATTERN.finditer(combined_lower):
            url_positions.append((m.start(), m.end()))

        def has_url_near(phrase_start: int, phrase_end: int, max_distance: int = 100) -> bool:
            """判断 phrase 附近 max_distance 字符内是否有 URL"""
            for us, ue in url_positions:
                if abs(us - phrase_end) <= max_distance or abs(ue - phrase_start) <= max_distance:
                    return True
            return False

        for rule_name, rule in KEYWORD_RULES.items():
            phrases = rule.get("phrases", [])
            keywords = rule.get("keywords", [])
            require_url = rule.get("require_url_proximity", 0)
            weight = rule.get("weight", 20)

            # ① 短语级匹配（优先级高）
            matched_phrases = []
            for phrase in phrases:
                ql = phrase.lower()
                for m in re.finditer(re.escape(ql), combined_lower):
                    if require_url and not has_url_near(m.start(), m.end(), require_url):
                        continue
                    matched_phrases.append(phrase)
                    break  # 每种短语只计一次

            # ② 关键词级匹配（降级）
            matched_kw = []
            for kw in keywords:
                if kw.lower() in combined_lower:
                    matched_kw.append(kw)

            all_matched = matched_phrases + matched_kw
            if not all_matched:
                continue

            # 密度惩罚：命中字符数 / 总字符数，避免长邮件靠堆词刷分
            matched_chars = sum(len(p) for p in all_matched)
            density = matched_chars / total_chars
            density_factor = 1.0
            if density < 0.001:      # 极低密度，弱化分数
                density_factor = 0.5
            elif density < 0.005:    # 低密度
                density_factor = 0.8

            # 短语匹配加权（短语比单词更可信）
            phrase_bonus = len(matched_phrases) * 5

            score = min(int((len(all_matched) * weight + phrase_bonus) * density_factor), 100)
            findings.append(f"{rule['description']}: 发现 {len(all_matched)} 处可疑表达{'(含URL邻近)' if require_url else ''}")

            # 映射维度
            if rule_name in ("urgency", "threat", "reward"):
                scores["social_engineering"] = max(scores["social_engineering"], score)
            elif rule_name in ("impersonation", "financial_tax"):
                scores["impersonation"] = max(scores["impersonation"], score)
            elif rule_name == "credential_harvesting":
                scores["credential_harvesting"] = max(scores["credential_harvesting"], score)

        # 计算欺骗意图（综合各维度）
        deception = int(
            scores["social_engineering"] * 0.4 +
            scores["impersonation"] * 0.3 +
            scores["credential_harvesting"] * 0.3
        )

        summary = "基于关键词规则引擎分析"
        if findings:
            summary += f"，发现 {len(findings)} 类可疑特征"
        else:
            summary += "，未发现明显可疑特征"

        return ContentAnalysisResult(
            social_engineering=scores["social_engineering"],
            impersonation=scores["impersonation"],
            credential_harvesting=scores["credential_harvesting"],
            deception_intent=deception,
            summary=summary,
            suspicious_indicators=findings,
        )

    def _calculate_content_score(self, result: ContentAnalysisResult) -> int:
        """计算内容综合得分"""
        # 四个维度的加权平均
        score = (
            result.social_engineering * 0.3 +
            result.impersonation * 0.25 +
            result.credential_harvesting * 0.25 +
            result.deception_intent * 0.2
        )
        return int(min(score, 100))

    def _detect_oauth_hijack_domain(self, text_content: str, urls: list[str] = None) -> str:
        """
        检测 OAuth 授权劫持：正文中出现授权关键词 且 链接指向非官方域名。
        返回可疑域名（若非官方），否则返回空字符串。
        """
        if not urls:
            return ""

        text_lower = text_content.lower()
        oauth_keywords = [
            "authorize", "allow access", "sign in with google", "sign in with microsoft",
            "sign in with apple", "sign in with facebook", "connect account",
            "google authorize", "microsoft authorize", "oauth", "access token",
            "sign in to continue", "continue with google", "log in with google",
            "log in with microsoft", "允许访问", "授权登录", "用谷歌账号", "用微软账号",
        ]
        if not any(kw in text_lower for kw in oauth_keywords):
            return ""

        # 官方 OAuth 域名白名单
        official_domains = {
            "google": {
                "accounts.google.com", "signin.google.com", "oauthperms.googleapis.com",
                "oauth2.googleapis.com", "google.com",
            },
            "microsoft": {
                "login.microsoftonline.com", "login.live.com", "account.microsoft.com",
                "login.windows.net", "microsoftonline.com",
            },
            "apple": {"appleid.apple.com", "signin.apple.com"},
            "facebook": {"facebook.com", "login.facebook.com"},
            "github": {"github.com", "login.github.com"},
        }

        all_official = set()
        for domains in official_domains.values():
            all_official.update(domains)

        from urllib.parse import urlparse
        for url in urls:
            try:
                domain = urlparse(url).netloc.lower().split(":")[0]
                if domain and domain not in all_official:
                    # 检查是否与 OAuth 关键词同时出现（已在前面确认有 OAuth 关键词）
                    return domain
            except Exception:
                pass

        return ""
