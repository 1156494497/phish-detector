"""
综合评分引擎
根据各维度分析结果，计算最终风险评分
"""
import re
import logging

from models import (
    DetectionResult, RiskLevel, DimensionScore, ScoreBreakdown,
    EmailMetadata, URLAnalysisResult, AttachmentAnalysisResult,
    ContentAnalysisResult, SenderAnalysisResult, HtmlAnalysisResult,
)
from config import (
    WEIGHT_URL, WEIGHT_ATTACHMENT, WEIGHT_CONTENT, WEIGHT_SENDER,
    SCORE_SAFE_MAX, SCORE_SUSPICIOUS_MAX,
    DIM_AMP_URL, DIM_AMP_ATTACHMENT, DIM_AMP_CONTENT, DIM_AMP_SENDER,
    SENDER_SCORE_BRAND_MISMATCH, SENDER_SCORE_NAME_EMAIL_MISMATCH,
    SENDER_SCORE_FREE_PROVIDER, SENDER_SCORE_SUSPICIOUS_TLD,
    SENDER_SCORE_INTERNAL_TYPOSQUAT, SENDER_SCORE_INTERNAL_NAME_CONTAIN,
    SENDER_SCORE_EMPTY_SENDER, SENDER_SCORE_SPF_FAIL, SENDER_SCORE_SPF_SOFTFAIL,
    SENDER_SCORE_SPF_NONE, SENDER_SCORE_DKIM_FAIL, SENDER_SCORE_DKIM_NONE,
    SENDER_SCORE_DMARC_FAIL, SENDER_SCORE_DMARC_NONE,
    SENDER_SCORE_REPLYTO_MISMATCH, SENDER_SCORE_RETURNPATH_MISMATCH,
    CORR_HIGH_THRESHOLD, CORR_MEDIUM_THRESHOLD,
    CORR_BONUS_3HIGH, CORR_BONUS_2HIGH, CORR_BONUS_ALL_MEDIUM,
    CORR_BONUS_PATTERN, CORR_BONUS_MAX,
    HTML_BONUS_PER_FINDING, HTML_BONUS_MAX,
)

logger = logging.getLogger(__name__)


class ScoringEngine:
    """综合评分引擎"""

    def calculate(
        self,
        metadata: EmailMetadata,
        url_result: URLAnalysisResult,
        attachment_result: AttachmentAnalysisResult,
        content_result: ContentAnalysisResult,
        html_analysis: HtmlAnalysisResult = None,
    ) -> DetectionResult:
        """
        计算综合风险评分

        Args:
            metadata: 邮件元数据
            url_result: URL 分析结果
            attachment_result: 附件分析结果
            content_result: 内容分析结果
            html_analysis: HTML 结构分析结果

        Returns:
            DetectionResult
        """
        # 1. 发件人风险分析
        sender_result = self._analyze_sender(metadata)

        # 2. 构建各维度评分
        dimensions = []

        # URL 维度
        dimensions.append(DimensionScore(
            name="链接风险",
            weight=WEIGHT_URL,
            score=url_result.max_score,
            findings=url_result.findings,
        ))

        # 附件维度
        dimensions.append(DimensionScore(
            name="附件风险",
            weight=WEIGHT_ATTACHMENT,
            score=attachment_result.max_score,
            findings=attachment_result.findings,
        ))

        # 内容维度
        dimensions.append(DimensionScore(
            name="内容风险",
            weight=WEIGHT_CONTENT,
            score=content_result.score,
            findings=content_result.suspicious_indicators,
        ))

        # 发件人维度
        dimensions.append(DimensionScore(
            name="发件人风险",
            weight=WEIGHT_SENDER,
            score=sender_result.score,
            findings=sender_result.findings,
        ))

        # 3. 计算加权总分（返回 breakdown 用于展示）
        total_score, breakdown = self._calculate_weighted_score(dimensions, attachment_result)

        # 4. 跨维度关联加分（传入原始结果以支持精细模式检测）
        correlation_bonus = self._apply_correlation_bonus(
            dimensions, url_result, attachment_result, content_result, html_analysis
        )
        total_score = min(total_score + correlation_bonus, 100)

        # 填充 breakdown 关联加分说明
        if correlation_bonus > 0:
            reasons = []
            core_dims = [d for d in dimensions if d.weight > 0]
            high = [d for d in core_dims if d.score > 60]
            if len(high) >= 3:
                reasons.append("3+维度高分")
            elif len(high) >= 2:
                reasons.append("2维度高分")
            if len([d for d in core_dims if d.score > 30]) >= 4:
                reasons.append("全面可疑")
            if any("仿冒" in str(f) for d in dimensions for f in d.findings):
                reasons.append("品牌仿冒")
            breakdown.correlation_bonus_detail = " + ".join(reasons) if reasons else f"+{correlation_bonus}分"

        # 5. HTML 结构风险附加评分
        if html_analysis and html_analysis.findings:
            html_bonus = min(len(html_analysis.findings) * HTML_BONUS_PER_FINDING, HTML_BONUS_MAX)
            total_score = min(total_score + html_bonus, 100)
            dimensions.append(DimensionScore(
                name="HTML结构风险",
                weight=0.0,
                score=html_bonus,
                findings=html_analysis.findings,
            ))

        # 6. 确定风险等级
        risk_level = self._determine_risk_level(total_score)

        # 7. 生成建议
        recommendation = self._generate_recommendation(risk_level, dimensions)

        return DetectionResult(
            total_score=total_score,
            risk_level=risk_level,
            dimensions=dimensions,
            score_breakdown=breakdown,
            email_metadata=metadata,
            url_analysis=url_result,
            attachment_analysis=attachment_result,
            content_analysis=content_result,
            sender_analysis=sender_result,
            html_analysis=html_analysis,
            correlation_bonus=correlation_bonus,
            recommendation=recommendation,
        )

    def _analyze_sender(self, metadata: EmailMetadata) -> SenderAnalysisResult:
        """分析发件人风险（含 SPF/DKIM/DMARC 认证）"""
        findings = []
        score = 0

        # 1. 显示名与邮箱地址不一致（基于 token 重合率）
        if metadata.sender_name and metadata.sender_email:
            name_lower = metadata.sender_name.lower()
            email_local = metadata.sender_email.split("@")[0].lower()

            # ① 品牌关键词检查
            brand_names = ["microsoft", "google", "apple", "amazon", "paypal", "netflix",
                           "腾讯", "阿里", "百度", "京东", "银行", "工商银行", "建设银行"]
            for brand in brand_names:
                if brand in name_lower and brand not in metadata.sender_domain:
                    score += SENDER_SCORE_BRAND_MISMATCH
                    findings.append(f"发件人显示名包含 '{brand}' 但邮箱域名不匹配: {metadata.sender_email}")
                    break

            # ② token 重合率检测（解决 "John Smith" vs "j.smith" 漏报）
            name_tokens = [t.strip(".-_") for t in re.split(r'[\s.\-_]+', name_lower) if t.strip()]
            email_tokens = [t.strip(".-_") for t in re.split(r'[\s.\-_/@]+', email_local) if t.strip()]
            if name_tokens and email_tokens and len(name_lower) > 3:
                overlap = sum(1 for nt in name_tokens if any(nt in et or et in nt for et in email_tokens))
                total_name_tokens = len(name_tokens)
                overlap_rate = overlap / total_name_tokens if total_name_tokens else 0
                if overlap_rate < 0.3:
                    score += SENDER_SCORE_NAME_EMAIL_MISMATCH
                    findings.append(f"发件人显示名 '{metadata.sender_name}' 与邮箱地址 '{metadata.sender_email}' 不一致（token 重合率 {overlap_rate:.0%}）")

        # 2. 免费邮箱提供商
        free_providers = {"gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "qq.com", "163.com", "126.com"}
        if metadata.sender_domain in free_providers:
            score += SENDER_SCORE_FREE_PROVIDER
            findings.append(f"发件人使用免费邮箱: {metadata.sender_domain}")

        # 3. 可疑 TLD
        suspicious_tlds = {".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".xyz", ".club", ".work"}
        for tld in suspicious_tlds:
            if metadata.sender_domain.endswith(tld):
                score += SENDER_SCORE_SUSPICIOUS_TLD
                findings.append(f"发件人域名使用可疑顶级域: {metadata.sender_domain}")
                break

        # 3.5 收件人域名仿冒检测（内部域名 typosquatting）
        if metadata.to and metadata.sender_domain:
            for recipient_addr in metadata.to:
                if "@" not in recipient_addr:
                    continue
                recipient_domain = recipient_addr.split("@")[-1].strip("<> ").lower()
                sender_domain = metadata.sender_domain.lower()
                if not recipient_domain or recipient_domain == sender_domain:
                    continue
                sender_name_part = sender_domain.split(".")[0]
                recipient_name_part = recipient_domain.split(".")[0]

                # a) 编辑距离 ≤ 3（如 desay-sv vs desaysv）
                dist = self._levenshtein_distance(sender_name_part, recipient_name_part)
                if 0 < dist <= 3:
                    score += SENDER_SCORE_INTERNAL_TYPOSQUAT
                    findings.append(
                        f"发件人域名 {sender_domain} 疑似仿冒内部域名 {recipient_domain}"
                        f"（编辑距离={dist}）"
                    )
                    break

                # b) 发件域名主名包含收件域名关键词（已有）
                if recipient_name_part in sender_name_part and sender_name_part != recipient_name_part:
                    score += SENDER_SCORE_INTERNAL_NAME_CONTAIN
                    findings.append(
                        f"发件人域名 {sender_domain} 包含内部域名关键词 '{recipient_name_part}'"
                    )
                    break

                # c) 发件人主名以收件人主名为前缀（如 microsoft-security 包含 microsoft）
                if sender_name_part.startswith(recipient_name_part + "-") or sender_name_part.startswith(recipient_name_part + "."):
                    score += SENDER_SCORE_INTERNAL_TYPOSQUAT
                    findings.append(
                        f"发件人域名 {sender_domain} 疑似仿冒内部域名 {recipient_domain}（主名前缀型）"
                    )
                    break

        # 4. 空发件人
        if not metadata.sender_email:
            score += SENDER_SCORE_EMPTY_SENDER
            findings.append("发件人地址为空")

        # 5. SPF/DKIM/DMARC 邮件认证解析
        spf_result, dkim_result, dmarc_result = self._parse_auth_results(metadata.headers)
        reply_to_mismatch, return_path_mismatch = self._check_address_mismatch(metadata)

        # SPF 评分
        if spf_result == "fail":
            score += SENDER_SCORE_SPF_FAIL
            findings.append("SPF 验证失败 — 发件人服务器未被授权发送此邮件")
        elif spf_result == "softfail":
            score += SENDER_SCORE_SPF_SOFTFAIL
            findings.append("SPF 软失败 — 发件人服务器可能未授权")
        elif spf_result == "pass":
            findings.append("SPF 验证通过")
        elif spf_result == "none":
            score += SENDER_SCORE_SPF_NONE
            findings.append("SPF 未配置 — 域名未设置 SPF 记录")

        # DKIM 评分
        if dkim_result == "fail":
            score += SENDER_SCORE_DKIM_FAIL
            findings.append("DKIM 验证失败 — 邮件签名无效或被篡改")
        elif dkim_result == "pass":
            findings.append("DKIM 验证通过")
        elif dkim_result == "none":
            score += SENDER_SCORE_DKIM_NONE
            findings.append("DKIM 未配置 — 域名未设置 DKIM 签名")

        # DMARC 评分
        if dmarc_result == "fail":
            score += SENDER_SCORE_DMARC_FAIL
            findings.append("DMARC 验证失败 — 邮件未通过域名对齐策略")
        elif dmarc_result == "pass":
            findings.append("DMARC 验证通过")
        elif dmarc_result == "none":
            score += SENDER_SCORE_DMARC_NONE
            findings.append("DMARC 未配置")

        # 6. Reply-To / Return-Path 不一致
        if reply_to_mismatch:
            score += SENDER_SCORE_REPLYTO_MISMATCH
            findings.append("Reply-To 地址与 From 地址不一致 — 可能在重定向回复")

        if return_path_mismatch:
            score += SENDER_SCORE_RETURNPATH_MISMATCH
            findings.append("Return-Path 地址与 From 地址不一致 — 可能伪造发件人")

        return SenderAnalysisResult(
            score=min(score, 100),
            display_name_mismatch="不一致" in str(findings),
            free_email_provider=metadata.sender_domain in free_providers,
            spf_result=spf_result,
            dkim_result=dkim_result,
            dmarc_result=dmarc_result,
            reply_to_mismatch=reply_to_mismatch,
            return_path_mismatch=return_path_mismatch,
            findings=findings,
        )

    def _parse_auth_results(self, headers: str) -> tuple[str, str, str]:
        """
        从邮件头解析 SPF/DKIM/DMARC 结果。

        用正则词边界匹配，避免 x-spf-pass 这类伪造 header 被误判。
        正确折叠长行后再解析。
        """
        if not headers:
            return "unknown", "unknown", "unknown"

        # ── Step 1: 折叠续行（RFC 2822 fold）─────────────────
        # 按 \n 切分后，将以 空格/Tab 开头的行合并到前一行
        raw_lines = headers.split("\n")
        folded_lines: list[str] = []
        for line in raw_lines:
            if line and line[0] in (" ", "\t") and folded_lines:
                folded_lines[-1] += " " + line.strip()
            else:
                folded_lines.append(line)

        # ── Step 2: 找 Authentication-Results（可能多个，取第一个含有效结果的）─
        spf = dkim = dmarc = "unknown"

        for line in folded_lines:
            ll = line.lower()
            if not ll.startswith("authentication-results:"):
                continue
            # 用词边界正则匹配 "spf=pass" 等，防止 x-spf-pass 误匹配
            for auth_type, result_var in [("spf", "spf"), ("dkim", "dkim"), ("dmarc", "dmarc")]:
                for verdict in ("pass", "fail", "softfail", "neutral", "none"):
                    # \bspf=verdict\b 确保不以字母数字/下划线开头/结尾
                    pattern = r'\b' + auth_type + r'=' + verdict + r'\b'
                    if re.search(pattern, ll):
                        if result_var == "spf":
                            spf = verdict
                        elif result_var == "dkim":
                            dkim = verdict
                        else:
                            dmarc = verdict

        # ── Step 3: 没有 Authentication-Results 时，用 Received-SPF ──
        if spf == "unknown":
            for line in folded_lines:
                ll = line.lower()
                if ll.startswith("received-spf:"):
                    # 解析完整 Received-SPF，而非只取第一个 token
                    # 格式: Received-SPF: pass (sender authorized) smtp.mailfrom=...
                    body = ll.split(":", 1)[1].strip()
                    tokens = body.split()
                    verdict = tokens[0] if tokens else ""
                    if verdict in ("pass", "fail", "softfail", "neutral", "none", "temperror", "permerror"):
                        spf = verdict
                    # 可选：解析 reason= / client-ip= 生成 finding（此处先保底）

        return spf, dkim, dmarc

    @staticmethod
    def _levenshtein_distance(s1: str, s2: str) -> int:
        """计算两个字符串的编辑距离"""
        if len(s1) < len(s2):
            return ScoringEngine._levenshtein_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)
        prev_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            curr_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = prev_row[j + 1] + 1
                deletions = curr_row[j] + 1
                substitutions = prev_row[j] + (c1 != c2)
                curr_row.append(min(insertions, deletions, substitutions))
            prev_row = curr_row
        return prev_row[-1]

    def _check_address_mismatch(self, metadata: EmailMetadata) -> tuple[bool, bool]:
        """
        检查 Reply-To 和 Return-Path 是否与 From 不一致（全地址解析）

        Returns: (reply_to_mismatch, return_path_mismatch)
        """
        from_email = metadata.sender_email.lower()
        reply_to_mismatch = False
        return_path_mismatch = False

        if not metadata.headers:
            return False, False

        # 解析所有 Reply-To 地址（全量解析，不再只判断第一个）
        all_reply_tos: list[str] = []
        for line in metadata.headers.split("\n"):
            ll = line.strip()
            if ll.lower().startswith("reply-to:"):
                # 可能有逗号分隔的多个地址
                addr_part = ll.split(":", 1)[1].strip()
                for raw_addr in addr_part.split(","):
                    addr = raw_addr.strip().lower()
                    if "<" in addr and ">" in addr:
                        addr = addr.split("<")[1].split(">")[0]
                    if addr:
                        all_reply_tos.append(addr)

        for reply_addr in all_reply_tos:
            if reply_addr and reply_addr != from_email:
                reply_to_mismatch = True
                break

        # 解析 Return-Path（全地址解析）
        all_return_paths: list[str] = []
        for line in metadata.headers.split("\n"):
            ll = line.strip()
            if ll.lower().startswith("return-path:"):
                addr_part = ll.split(":", 1)[1].strip()
                if "<" in addr_part and ">" in addr_part:
                    addr_part = addr_part.split("<")[1].split(">")[0]
                if addr_part:
                    all_return_paths.append(addr_part.lower())

        for rp_addr in all_return_paths:
            if rp_addr and rp_addr != from_email:
                return_path_mismatch = True
                break

        return reply_to_mismatch, return_path_mismatch

    def _calculate_weighted_score(
        self,
        dimensions: list[DimensionScore],
        attachment_result: AttachmentAnalysisResult,
    ) -> tuple[int, ScoreBreakdown]:
        """
        计算加权总分，同时返回得分瀑布详情（ScoreBreakdown）。

        Returns:
            (加权总分, ScoreBreakdown)
        """
        breakdown = ScoreBreakdown()
        total = 0.0
        total_weight = 0.0

        # 先填充各维度的 raw_score
        for dim in dimensions:
            dim.raw_score = dim.score

        # 放大系数
        amp = {
            "链接风险": DIM_AMP_URL,
            "附件风险": DIM_AMP_ATTACHMENT,
            "内容风险": DIM_AMP_CONTENT,
            "发件人风险": DIM_AMP_SENDER,
        }

        for dim in dimensions:
            if dim.name == "附件风险" and not attachment_result.attachments_analyzed:
                continue

            # 放大后的分
            a = amp.get(dim.name, 1.0)
            dim.score = int(dim.score * a)

            # 填充 breakdown
            if dim.name == "链接风险":
                breakdown.url_score = dim.raw_score
                breakdown.url_contribution = dim.score
                breakdown.dim_amp_applied["链接风险"] = a
            elif dim.name == "附件风险":
                breakdown.attachment_score = dim.raw_score
                breakdown.attachment_contribution = dim.score
                breakdown.dim_amp_applied["附件风险"] = a
            elif dim.name == "内容风险":
                breakdown.content_score = dim.raw_score
                breakdown.content_contribution = dim.score
                breakdown.dim_amp_applied["内容风险"] = a
            elif dim.name == "发件人风险":
                breakdown.sender_score = dim.raw_score
                breakdown.sender_contribution = dim.score
                breakdown.dim_amp_applied["发件人风险"] = a

            total += dim.score * dim.weight
            total_weight += dim.weight

        # 归一化
        if total_weight > 0:
            final_score = total / total_weight
        else:
            final_score = 0

        return int(min(final_score, 100)), breakdown

    def _apply_correlation_bonus(
        self,
        dimensions: list[DimensionScore],
        url_result: URLAnalysisResult,
        attachment_result: AttachmentAnalysisResult,
        content_result: ContentAnalysisResult,
        html_analysis: HtmlAnalysisResult = None,
    ) -> int:
        """
        跨维度关联加分：多维度同时高分时额外加分
        钓鱼邮件通常多个维度同时异常，关联命中比单一维度更可信
        """
        # 排除 weight=0 的附加维度（如 HTML结构风险）
        core_dims = [d for d in dimensions if d.weight > 0]
        high_dims = [d for d in core_dims if d.score > CORR_HIGH_THRESHOLD]
        medium_dims = [d for d in core_dims if d.score > CORR_MEDIUM_THRESHOLD]

        bonus = 0

        # 3+ 个维度同时高分 → +CORR_BONUS_3HIGH
        if len(high_dims) >= 3:
            bonus += CORR_BONUS_3HIGH
        # 2 个维度同时高分 → +CORR_BONUS_2HIGH
        elif len(high_dims) >= 2:
            bonus += CORR_BONUS_2HIGH

        # 4 个维度全部中等以上 → +CORR_BONUS_ALL_MEDIUM（全面可疑）
        if len(medium_dims) >= 4:
            bonus += CORR_BONUS_ALL_MEDIUM

        # ── 基础模式检测（通过 findings 文本匹配）──────────────
        # 品牌仿冒 + 发件人不一致 + 链接风险 三重命中
        has_brand_impersonation = any("仿冒" in str(f) or "冒充" in str(f) for d in dimensions for f in d.findings)
        has_sender_mismatch = any("不一致" in str(f) or "不匹配" in str(f) for d in dimensions for f in d.findings)
        has_url_risk = any(d.name == "链接风险" and d.score > CORR_MEDIUM_THRESHOLD + 20 for d in dimensions)

        if has_brand_impersonation and has_sender_mismatch and has_url_risk:
            bonus += CORR_BONUS_PATTERN

        # 凭证窃取 + 紧迫话术 + 链接风险 三重命中
        has_credential = any("凭证" in str(f) or "密码" in str(f) for d in dimensions for f in d.findings)
        has_urgency = any("紧迫" in str(f) or "紧急" in str(f) or "urgent" in str(f).lower() for d in dimensions for f in d.findings)

        if has_credential and has_urgency and has_url_risk:
            bonus += CORR_BONUS_PATTERN

        # ── 精细模式（使用原始分析结果）────────────────────

        # 模式1: 二维码钓鱼
        has_qr = False
        if html_analysis:
            html_text = " ".join(html_analysis.findings) if html_analysis.findings else ""
            if any(kw in html_text.lower() for kw in ["qr", "二维码", "qrcode", "qr-code"]):
                has_qr = True
            if html_analysis.tracking_pixel_urls:
                for p in html_analysis.tracking_pixel_urls:
                    if any(api in p.lower() for api in ["qr", "qrcode", "goqr", "api.qr"]):
                        has_qr = True
        if has_qr and has_url_risk:
            bonus += 10

        # 模式2: 多域名跳转链
        if url_result and url_result.urls_analyzed:
            for u in url_result.urls_analyzed:
                if u.redirect_chain and len(u.redirect_chain) >= 2 and u.final_domain and u.final_domain != u.domain:
                    bonus += 10
                    break

        # 模式3: 附件 + 链接 双高
        att_score = next((d.score for d in core_dims if d.name == "附件风险"), 0)
        if att_score > 60 and url_result and url_result.max_score > 60:
            bonus += 8

        # 模式4: 发件人域名年龄 < 30 天 + 内容里有链接
        sender_dim = next((d for d in core_dims if d.name == "发件人风险"), None)
        url_dim = next((d for d in core_dims if d.name == "链接风险"), None)
        if sender_dim and sender_dim.score > 40 and url_dim and url_dim.score > 20:
            if url_result and url_result.urls_analyzed:
                for u in url_result.urls_analyzed:
                    if u.domain_age_days is not None and u.domain_age_days < 30:
                        bonus += 10
                        break

        # ── 新增：OAuth 授权劫持 → 直接标记 critical ──────────
        if content_result and getattr(content_result, "oauth_hijack_detected", False):
            bonus += 15

        # ── 新增：假登录框 + URL 指向非官方域名 → 高危组合 ──
        if html_analysis and html_analysis.has_fake_login_page and url_result and url_result.max_score > 30:
            bonus += 15

        return min(bonus, CORR_BONUS_MAX)

    def _determine_risk_level(self, score: int) -> RiskLevel:
        """确定风险等级"""
        if score <= SCORE_SAFE_MAX:
            return RiskLevel.SAFE
        elif score <= SCORE_SUSPICIOUS_MAX:
            return RiskLevel.SUSPICIOUS
        else:
            return RiskLevel.MALICIOUS

    def _generate_recommendation(self, risk_level: RiskLevel, dimensions: list[DimensionScore]) -> str:
        """生成处置建议"""
        if risk_level == RiskLevel.SAFE:
            return "未发现明显钓鱼邮件特征，可正常处理。建议仍保持基本警惕。"
        elif risk_level == RiskLevel.SUSPICIOUS:
            suspicious_dims = [d.name for d in dimensions if d.score > 30]
            return (
                f"存在部分风险指标（{', '.join(suspicious_dims)}），建议人工复核。"
                "请勿点击邮件中的链接或下载可疑附件，必要时联系安全团队确认。"
            )
        else:
            high_risk_dims = [d.name for d in dimensions if d.score > 60]
            return (
                f"高度疑似钓鱼邮件！主要风险来源：{', '.join(high_risk_dims)}。"
                "建议立即拦截，不要回复邮件、点击链接或打开附件。"
                "请将此邮件转发给安全团队进行进一步分析。"
            )
