"""
钓鱼邮件检测报告生成器（大白话分层版）

报告分三层，越往上越口语化、越紧要：
  第 1 层  一眼结论         —— 这封邮件安不安全、为什么、你该怎么办
  第 2 层  关键问题清单     —— 把命中点逐条用大白话列出（带红/黄/绿圆点）
  第 3 层  技术细节（可折叠） —— 给工程师看的原始数据：认证、URL/附件明细、维度、邮件头

CSS 浅色打印友好，<details> 折叠技术细节；整页自包含可离线打开。
"""
import html
from datetime import datetime

from models import DetectionResult, RiskLevel
from terminology import (
    translate_finding,
    glossary_hint,
    build_action_list,
    one_line_reason,
)


class ReportGenerator:
    """生成大白话分层 HTML 检测报告"""

    # ---- 通用助手 ----
    def _e(self, s) -> str:
        return html.escape(str(s)) if s is not None else ""

    def _risk_color(self, level: RiskLevel) -> str:
        return {"safe": "#10b981", "suspicious": "#f59e0b", "malicious": "#ef4444"}[level.value]

    def _risk_emoji(self, level: RiskLevel) -> str:
        return {"safe": "🟢", "suspicious": "🟡", "malicious": "🔴"}[level.value]

    def _risk_text(self, level: RiskLevel) -> str:
        return {"safe": "安全", "suspicious": "可疑", "malicious": "高危"}[level.value]

    def _risk_headline(self, level: RiskLevel) -> str:
        return {
            "safe": "这封邮件看起来是安全的",
            "suspicious": "这封邮件有些可疑，先别急着操作",
            "malicious": "这封邮件很危险，别点链接也别开附件",
        }[level.value]

    def _sev_dot_css(self, score: int) -> str:
        if score <= 30:
            return "dot dot-safe"
        if score <= 60:
            return "dot dot-warn"
        return "dot dot-danger"

    def _plain_for(self, text: str) -> str:
        """取某条 finding 的大白话：优先 app 注入的 plain_map，其次正则 translate_finding。"""
        if not text:
            return text
        if text in self._plain_computed:
            return self._plain_computed[text]
        # 注入优先（LLM/批量翻译更自然），正则兜底
        t = self._plain_map.get(text) or translate_finding(text)
        self._plain_computed[text] = t
        return t

    # =========================================================
    # 主入口
    # =========================================================
    def generate(self, result: DetectionResult, elapsed: float, filename: str = "",
                 plain_map: dict[str, str] | None = None) -> str:
        """
        生成报告。

        plain_map: 可选，{finding原文: 大白话}。由 app 用 FindingsTranslator 预先翻译好；
                   不传时第二层会用正则 translate_finding 兜底（旧逻辑，仍可用）。
        """
        self._plain_map = plain_map or {}
        # 缓存一次性翻译结果，避免重复调用正则
        self._plain_computed: dict[str, str] = {}
        body = [
            self._gen_header(result, elapsed, filename),
            self._gen_layer1_conclusion(result),
            self._gen_layer2_issues(result),
            self._gen_layer3_details(result),
            self._gen_footer(),
        ]
        # 用完即清，避免 ReportGenerator 复用时串数据
        self._plain_map = {}
        self._plain_computed = {}
        css = self._get_css()
        subject = result.email_metadata.subject if result.email_metadata else ""
        return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>钓鱼邮件检测报告 - {self._e(subject or '未知主题')}</title>
<style>{css}</style>
</head>
<body>
<div class="report">
{''.join(body)}
</div>
<script>
  // 打印/另存按钮
  function printReport(){{ window.print(); }}
</script>
</body>
</html>"""

    # =========================================================
    # 报告头（带风险条 + 基本信息）
    # =========================================================
    def _gen_header(self, result: DetectionResult, elapsed: float, filename: str) -> str:
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        color = self._risk_color(result.risk_level)
        text = self._risk_text(result.risk_level)
        meta = result.email_metadata
        sender = self._e(f"{meta.sender_name} <{meta.sender_email}>") if meta else "—"
        subject = self._e(meta.subject or "（无主题）") if meta else "—"
        date = self._e(meta.date or "—") if meta else "—"
        return f"""
<!-- 报告头 -->
<div class="doc-head" style="border-top:6px solid {color};">
  <div class="doc-head-top">
    <div>
      <div class="kicker">PhishGuard 钓鱼邮件检测报告</div>
      <div class="filename">源文件：{self._e(filename)}</div>
      <div class="meta-line">生成时间：{now}　·　分析耗时：{elapsed:.2f}s</div>
    </div>
    <div class="doc-actions no-print">
      <button class="btn-print" onclick="printReport()">🖨️ 打印 / 另存为 PDF</button>
    </div>
  </div>

  <!-- 风利分 + 等级 -->
  <div class="score-strip">
    <div class="score-circle" style="border-color:{color};">
      <div class="score-num" style="color:{color};">{result.total_score}</div>
      <div class="score-unit">/100</div>
    </div>
    <div class="score-side">
      <div class="risk-pill" style="background:{color};">{self._risk_emoji(result.risk_level)} {text}</div>
      <div class="risk-scale">
        <span class="{'seg on' if result.risk_level==RiskLevel.SAFE else 'seg'}">安全 0–30</span>
        <span class="{'seg on' if result.risk_level==RiskLevel.SUSPICIOUS else 'seg'}">可疑 31–60</span>
        <span class="{'seg on' if result.risk_level==RiskLevel.MALICIOUS else 'seg'}">高危 61–100</span>
      </div>
      <div class="meta-line">主题：{subject}　·　发件人：{sender}　·　日期：{date}</div>
    </div>
  </div>
</div>"""

    # =========================================================
    # 第 1 层 —— 一眼结论 + 得分瀑布
    # =========================================================
    def _gen_layer1_conclusion(self, result: DetectionResult) -> str:
        headline = self._risk_headline(result.risk_level)
        reason = one_line_reason(result)
        actions = build_action_list(result)
        color = self._risk_color(result.risk_level)

        actions_html = "".join(f'<li>{self._e(a)}</li>' for a in actions)

        # 得分瀑布条
        breakdown_html = self._gen_score_waterfall(result)

        return f"""
<!-- 第 1 层：一眼结论 -->
<div class="layer" style="border-left:5px solid {color};">
  <h2 class="layer-h">① 一眼结论</h2>
  <div class="verdict" style="color:{color};">
    {self._risk_emoji(result.risk_level)} <span class="verdict-big">{self._e(headline)}</span>
  </div>
  <div class="why">
    <span class="why-k">为什么：</span>
    {self._e(reason)}　
    <span class="score-extra">（综合评分 {result.total_score}/100，评级「{self._risk_text(result.risk_level)}」）</span>
  </div>
  {breakdown_html}
  <div class="advice">
    <div class="advice-h">你该怎么办：</div>
    <ol class="advice-list">{actions_html}</ol>
  </div>
</div>"""

    def _gen_score_waterfall(self, result: DetectionResult) -> str:
        """生成得分瀑布横向条：各维度加权贡献 + 关联加分"""
        bd = result.score_breakdown
        if not bd:
            return ""

        total = result.total_score
        if total == 0:
            return ""

        items = []
        # 各维度贡献
        contribs = [
            ("🔗 链接", bd.url_contribution),
            ("📎 附件", bd.attachment_contribution),
            ("📝 内容", bd.content_contribution),
            ("👤 发件人", bd.sender_contribution),
        ]
        for label, contrib in contribs:
            if contrib > 0:
                pct = min(contrib / total * 100, 100)
                items.append((label, contrib, pct))

        if not items:
            return ""

        bars_html = "".join(
            f'<div class="wf-row">'
            f'<span class="wf-label">{label}</span>'
            f'<div class="wf-bar-bg"><div class="wf-bar-fill" style="width:{pct:.1f}%;"></div></div>'
            f'<span class="wf-score">+{score}</span>'
            f'</div>'
            for label, score, pct in items
        )

        # 关联加分条
        corr_html = ""
        if result.correlation_bonus > 0:
            corr_pct = result.correlation_bonus / total * 100
            corr_label = bd.correlation_bonus_detail or "关联加分"
            corr_html = (
                f'<div class="wf-row wf-corr">'
                f'<span class="wf-label">⚡ 关联加分</span>'
                f'<div class="wf-bar-bg"><div class="wf-bar-fill wf-corr-fill" style="width:{corr_pct:.1f}%;"></div></div>'
                f'<span class="wf-score">+{result.correlation_bonus}</span>'
                f'</div>'
            )

        return f"""
  <!-- 得分瀑布 -->
  <div class="wf-container">
    <div class="wf-hint">得分构成（满分 {result.total_score}）</div>
    {bars_html}
    {corr_html}
  </div>"""

    # =========================================================
    # 第 2 层 —— 关键问题清单（大白话逐条）
    # =========================================================
    def _gen_layer2_issues(self, result: DetectionResult) -> str:
        blocks = []

        # 链接
        ua = result.url_analysis
        if ua and (ua.findings or (ua.urls_analyzed and len(ua.urls_analyzed) > 0)):
            blocks.append(self._layer2_block(
                "🔗 链接", ua.max_score,
                ua.findings,
                extra_items=self._url_plain_extras(ua),
            ))

        # 附件
        aa = result.attachment_analysis
        if aa and (aa.findings or (aa.attachments_analyzed and len(aa.attachments_analyzed) > 0)):
            blocks.append(self._layer2_block(
                "📎 附件", aa.max_score,
                aa.findings,
                extra_items=self._att_plain_extras(aa),
            ))

        # 内容
        ca = result.content_analysis
        if ca and (ca.suspicious_indicators or ca.summary):
            plain_inds = ca.suspicious_indicators  # 直接展示，通常已是口语
            blocks.append(self._layer2_block(
                "📝 正文话术", ca.score,
                plain_inds,
                prose=ca.summary,
            ))

        # 发件人
        sa = result.sender_analysis
        if sa and sa.findings:
            blocks.append(self._layer2_block(
                "👤 发件人", sa.score,
                sa.findings,
            ))

        if not blocks:
            body = '<p class="empty">没有发现明显可疑的问题点。👍</p>'
        else:
            body = "\n".join(blocks)

        return f"""
<!-- 第 2 层：关键问题清单 -->
<div class="layer">
  <h2 class="layer-h">② 关键问题清单（大白话）</h2>
  <p class="layer-note">下面把这次检测命中的问题点用人话说一遍，圆点颜色表示严重程度——
    <span class="legend"><i class="dot-inline dot-safe"></i>正常</span>
    <span class="legend"><i class="dot-inline dot-warn"></i>留意</span>
    <span class="legend"><i class="dot-inline dot-danger"></i>危险</span>
  </p>
  {body}
</div>"""

    def _layer2_block(self, title: str, score: int, findings, prose: str = "", extra_items=None) -> str:
        sev = self._sev_dot_css(score)
        prose_html = f'<p class="prose">{self._e(prose)}</p>' if prose else ""
        items_html = ""
        for f in (findings or []):
            items_html += (
                f'<div class="issue {sev}">'
                f'<i class="dot-inline {sev[4:]}"></i>'
                f'<span>{self._e(self._plain_for(f))}</span>'
                f'</div>'
            )
        # 附加大白话项（如 URL/附件明细里抽取的高危点）
        for it in (extra_items or []):
            items_html += (
                f'<div class="issue {sev}">'
                f'<i class="dot-inline {sev[4:]}"></i>'
                f'<span>{self._e(it)}</span>'
                f'</div>'
            )
        return f"""
  <div class="issue-block">
    <div class="issue-block-h">
      <span class="ibi-title">{title}</span>
      <span class="ibi-score badge" style="{self._badge_style(score)}">{score} 分</span>
    </div>
    {prose_html}
    {items_html if items_html else '<div class="empty">未发现明显问题。</div>'}
  </div>"""

    def _badge_style(self, score: int) -> str:
        c = "#10b981" if score <= 30 else ("#f59e0b" if score <= 60 else "#ef4444")
        return f"background:{c}22;color:{c};"

    # 链接/附件明细里的高危点 → 大白话（放进第 2 层清单）
    def _url_plain_extras(self, ua) -> list[str]:
        out = []
        for u in (ua.urls_analyzed or []):
            if u.href_mismatch:
                out.append(
                    f"链接「{u.display_text or u.url}」看着正常，实际会跳到 {u.domain}，文字和真实地址对不上。"
                )
            if u.vt_checked and u.vt_malicious_count > 0:
                out.append(
                    f"链接 {u.domain} 在 VirusTotal 上有 {u.vt_malicious_count}/{u.vt_total_engines} 款杀毒引擎报毒。"
                )
            if u.typosquat_brand:
                out.append(f"链接 {u.domain} 在仿冒「{u.typosquat_brand}」。")
        return out

    def _att_plain_extras(self, aa) -> list[str]:
        out = []
        for a in (aa.attachments_analyzed or []):
            if a.vt_checked and a.vt_malicious_count > 0:
                out.append(
                    f"附件 {a.filename} 在 VirusTotal 上有 {a.vt_malicious_count}/{a.vt_total_engines} 款杀毒引擎报毒。"
                )
            if a.is_disguised:
                out.append(
                    f"附件 {a.filename} 后缀被伪装过（看着像 {a.expected_type}，实际是 {a.actual_type}）。"
                )
            if a.is_encrypted:
                out.append(f"附件 {a.filename} 是加了密码的压缩包，里面藏的东西安全软件看不到。")
        return out

    # =========================================================
    # 第 3 层 —— 技术细节（折叠）
    # =========================================================
    def _gen_layer3_details(self, result: DetectionResult) -> str:
        inner = []
        # 认证
        auth = self._gen_detail_auth(result.sender_analysis)
        if auth:
            inner.append(auth)
        inner.append(self._gen_detail_urls(result.url_analysis))
        inner.append(self._gen_detail_attachments(result.attachment_analysis))
        inner.append(self._gen_detail_content(result.content_analysis))
        inner.append(self._gen_detail_sender(result.sender_analysis))
        inner.append(self._gen_detail_html(result.html_analysis))
        inner.append(self._gen_detail_dimensions(result))
        inner.append(self._gen_detail_headers(result.email_metadata))

        return f"""
<!-- 第 3 层：技术细节 -->
<div class="layer">
  <h2 class="layer-h">③ 技术细节（可选）</h2>
  <p class="layer-note">下面是给工程师/安全人员看的原始数据，普通人看①②就够了。</p>
  {''.join(inner)}
</div>"""

    def _detail(self, title: str, content: str, hint: str = "") -> str:
        hint_html = f'<div class="term-hint">{self._e(hint)}</div>' if hint else ""
        return f"""
  <details class="det">
    <summary>{title}</summary>
    <div class="det-body">{hint_html}{content}</div>
  </details>"""

    def _gen_detail_auth(self, sender) -> str:
        if not sender:
            return ""
        def badge(r: str) -> str:
            cls = {
                "pass": "ok", "softpass": "warn", "softfail": "warn",
                "fail": "bad", "none": "warn", "unknown": "muted",
            }.get((r or "").lower(), "muted")
            return f'<span class="tag tag-{cls}">{self._e(r)}</span>'

        rows = (
            f'<table class="kv"><tr><td class="k">SPF</td><td>{badge(sender.spf_result)}</td></tr>'
            f'<tr><td class="k">DKIM</td><td>{badge(sender.dkim_result)}</td></tr>'
            f'<tr><td class="k">DMARC</td><td>{badge(sender.dmarc_result)}</td></tr>'
            f'<tr><td class="k">Reply-To 与发件人不一致</td><td>{ "是 ⚠️" if sender.reply_to_mismatch else "否" }</td></tr>'
            f'<tr><td class="k">Return-Path 与发件人不一致</td><td>{ "是 ⚠️" if sender.return_path_mismatch else "否" }</td></tr>'
            f'</table>'
        )
        hint = (
            f"{glossary_hint('SPF')}　{glossary_hint('DKIM')}　{glossary_hint('DMARC')}　"
            f"{glossary_hint('Reply-To')}　{glossary_hint('Return-Path')}"
        )
        return self._detail("🔐 邮件认证（SPF / DKIM / DMARC）", rows, hint)

    def _gen_detail_urls(self, ua) -> str:
        if not ua or not ua.urls_analyzed:
            return self._detail("🔗 链接明细", '<p class="empty">邮件中未发现链接。</p>')
        rows = ""
        for u in ua.urls_analyzed:
            sc = self._badge_style(u.score)
            vt = f'{u.vt_malicious_count}/{u.vt_total_engines} 引擎' if u.vt_checked else "—"
            if u.vt_checked and u.vt_malicious_count > 0:
                vt = f'<span style="color:#dc2626;">{vt}</span>'
            mismatch = '<span class="tag tag-bad">不一致</span>' if u.href_mismatch else "—"
            age = f"{u.domain_age_days}天" if u.domain_age_days is not None else "—"
            brand = self._e(u.typosquat_brand) if u.typosquat_brand else "—"
            rows += (
                '<tr>'
                f'<td class="mono break">{self._e(u.url)}</td>'
                f'<td>{self._e(u.domain)}</td>'
                f'<td class="ctr"><span class="tag" style="{sc}">{u.score}</span></td>'
                f'<td>{self._e(u.display_text) if u.display_text else "—"}</td>'
                f'<td class="ctr">{mismatch}</td>'
                f'<td class="ctr">{age}</td>'
                f'<td class="ctr">{self._e(brand)}</td>'
                f'<td class="ctr">{vt}</td>'
                '</tr>'
            )
        tab = (
            '<table class="data">'
            '<thead><tr><th>URL</th><th>域名</th><th>分</th><th>显示文本</th><th>不一致</th>'
            '<th>域名年龄</th><th>仿冒品牌</th><th>VirusTotal</th></tr></thead>'
            f'<tbody>{rows}</tbody></table>'
        )
        findings = ""
        if ua.findings:
            findings = '<ul class="findings">' + "".join(f"<li>{self._e(f)}</li>" for f in ua.findings) + "</ul>"
        hint = f"{glossary_hint('VirusTotal')}"
        return self._detail(f"🔗 链接明细（共 {len(ua.urls_analyzed)} 条，最高 {ua.max_score} 分）", tab + findings, hint)

    def _gen_detail_attachments(self, aa) -> str:
        if not aa or not aa.attachments_analyzed:
            return self._detail("📎 附件明细", '<p class="empty">邮件中无附件。</p>')
        rows = ""
        for a in aa.attachments_analyzed:
            sc = self._badge_style(a.score)
            danger_css = {
                "high": "tag-bad", "medium": "tag-warn", "low": "tag-ok",
            }.get(a.file_type_danger, "tag-muted")
            encrypted = "🔒 是" if a.is_encrypted else "否"
            inner = ", ".join(a.inner_files[:5]) if a.inner_files else "—"
            macro = "是 ⚠️" if a.has_macro else "否"
            vt = f'{a.vt_malicious_count}/{a.vt_total_engines}' if a.vt_checked else "—"
            if a.vt_checked and a.vt_malicious_count > 0:
                vt = f'<span style="color:#dc2626;">{vt}</span>'
            link = f' <a href="{self._e(a.vt_link)}" target="_blank">VT链接</a>' if a.vt_link else ""
            rows += (
                '<tr>'
                f'<td class="break">{self._e(a.filename)}</td>'
                f'<td class="ctr">{self._e(a.extension)}</td>'
                f'<td class="ctr"><span class="tag {danger_css}">{self._e(a.file_type_danger)}</span></td>'
                f'<td class="ctr"><span class="tag" style="{sc}">{a.score}</span></td>'
                f'<td class="ctr">{macro}</td>'
                f'<td class="ctr">{encrypted}</td>'
                f'<td class="small">{self._e(inner)}</td>'
                f'<td class="ctr">{vt}{link}</td>'
                '</tr>'
            )
        tab = (
            '<table class="data">'
            '<thead><tr><th>文件名</th><th>后缀</th><th>危险级</th><th>分</th>'
            '<th>宏</th><th>加密包</th><th>内部文件</th><th>VirusTotal</th></tr></thead>'
            f'<tbody>{rows}</tbody></table>'
        )
        findings = ""
        if aa.findings:
            findings = '<ul class="findings">' + "".join(f"<li>{self._e(f)}</li>" for f in aa.findings) + "</ul>"
        hint = " ".join(glossary_hint(t) for t in ["VBA宏", "SHA256", "VirusTotal"])
        return self._detail(f"📎 附件明细（共 {len(aa.attachments_analyzed)} 个，最高 {aa.max_score} 分）", tab + findings, hint)

    def _gen_detail_content(self, ca) -> str:
        if not ca:
            return ""
        def bar(name, v):
            c = "#10b981" if v <= 30 else ("#f59e0b" if v <= 60 else "#ef4444")
            return (
                f'<div class="cbar-row"><span class="cbar-k">{name}</span>'
                f'<div class="cbar"><div class="cbar-fill" style="width:{v}%;background:{c};"></div></div>'
                f'<span style="color:{c};font-weight:600;">{v}</span></div>'
            )
        bars = (
            bar("社会工程学", ca.social_engineering)
            + bar("冒充风险", ca.impersonation)
            + bar("凭证窃取", ca.credential_harvesting)
            + bar("欺骗意图", ca.deception_intent)
        )
        method = '<span class="tag tag-ok">LLM 分析</span>' if ca.used_llm else '<span class="tag tag-warn">规则引擎</span>'
        attack_tag = ""
        if ca.attack_type_display:
            attack_tag = f' <span class="tag tag-bad">{self._e(ca.attack_type_display)}</span>'
        prose = f'<div class="prose">{method}{attack_tag} {self._e(ca.summary or "无分析结论")}</div>'
        inds = ""
        if ca.suspicious_indicators:
            inds = '<ul class="findings">' + "".join(f"<li>{self._e(i)}</li>" for i in ca.suspicious_indicators) + "</ul>"
        body = prose + f'<div class="cbars">{bars}</div>' + f'<div class="kv"><div class="k">综合内容得分</div><div class="v">{ca.score}</div></div>' + inds
        return self._detail(f"📝 内容分析明细（内容分 {ca.score}）", body)

    def _gen_detail_sender(self, sender) -> str:
        if not sender:
            return ""
        rows = (
            '<table class="kv">'
            f'<tr><td class="k">显示名与地址不一致</td><td>{ "是 ⚠️" if sender.display_name_mismatch else "否" }</td></tr>'
            f'<tr><td class="k">免费邮箱</td><td>{ "是" if sender.free_email_provider else "否" }</td></tr>'
            f'<tr><td class="k">可疑顶级域</td><td>{ "是 ⚠️" if sender.suspicious_tld else "否" }</td></tr>'
            f'<tr><td class="k">域名年龄</td><td>{ (str(sender.domain_age_days)+"天") if sender.domain_age_days is not None else "—" }</td></tr>'
            '</table>'
        )
        findings = ""
        if sender.findings:
            findings = '<ul class="findings">' + "".join(f"<li>{self._e(f)}</li>" for f in sender.findings) + "</ul>"
        hint = glossary_hint("顶级域")
        return self._detail(f"👤 发件人明细（发件人分 {sender.score}）", rows + findings, hint)

    def _gen_detail_html(self, ha) -> str:
        if not ha or not ha.findings:
            return ""
        form_actions = "<br>".join(self._e(a) for a in ha.form_actions) if ha.form_actions else "—"
        fields = self._e(", ".join(ha.form_input_fields)) if ha.form_input_fields else "—"
        pixels = "<br>".join(self._e(u) for u in ha.tracking_pixel_urls[:5]) if ha.tracking_pixel_urls else "—"
        # 假登录框高危标记
        fake_login_warn = ""
        if ha.has_fake_login_page:
            fake_login_warn = f'<div class="tag tag-bad" style="margin-bottom:8px;">&#9888; 假登录框警告：疑似仿冒 {ha.fake_login_brand} 登录界面（凭据窃取陷阱）</div>'
        rows = (
            '<table class="kv">'
            f'<tr><td class="k">是否含表单</td><td>{ "是 ⚠️" if ha.has_form else "否" }</td></tr>'
            f'<tr><td class="k">表单输入字段</td><td>{fields}</td></tr>'
            f'<tr><td class="k">表单提交地址(action)</td><td>{form_actions}</td></tr>'
            f'<tr><td class="k">是否含追踪像素</td><td>{ "是 ⚠️" if ha.has_tracking_pixel else "否" }</td></tr>'
            f'<tr><td class="k">追踪像素地址</td><td>{pixels}</td></tr>'
            f'<tr><td class="k">隐藏元素数</td><td>{ha.hidden_text_count}</td></tr>'
            f'<tr><td class="k">数据外传</td><td>{ "是 ⚠️" if ha.has_external_data_exfil else "否" }</td></tr>'
            f'<tr><td class="k">外传目标域名</td><td>{", ".join(self._e(d) for d in ha.exfil_domains[:5]) if ha.exfil_domains else "—"}</td></tr>'
            f'<tr><td class="k">隐藏URL</td><td>{ "是 ⚠️" if ha.has_hidden_base64_url else "否" }</td></tr>'
            f'<tr><td class="k">反分析代码</td><td>{ "是 ⚠️" if ha.has_anti_analysis else "否" }</td></tr>'
            f'<tr><td class="k">反机器人检测</td><td>{ "是 ⚠️" if ha.has_anti_bot else "否" }</td></tr>'
            '</table>'
        )
        findings = '<ul class="findings">' + "".join(f"<li>{self._e(f)}</li>" for f in ha.findings) + "</ul>"
        hint = " ".join(glossary_hint(t) for t in ["HTML表单", "追踪像素", "隐藏元素"])
        return self._detail("🏗️ HTML 结构明细" + ("（含假登录框/JS行为检测）" if ha.has_fake_login_page or ha.has_external_data_exfil else ""), fake_login_warn + rows + findings, hint)

    def _gen_detail_dimensions(self, result: DetectionResult) -> str:
        if not result.dimensions:
            return ""
        rows = ""
        for d in result.dimensions:
            sc = self._badge_style(d.score)
            findings = "<br>".join(self._e(f) for f in d.findings[:10]) if d.findings else "—"
            raw_display = f'{d.raw_score}→{d.score}' if d.raw_score != d.score else str(d.score)
            amp_note = " *" if d.raw_score != d.score else ""
            rows += (
                '<tr>'
                f'<td>{self._e(d.name)}</td>'
                f'<td class="ctr">{d.weight:.0%}</td>'
                f'<td class="ctr"><span class="tag" style="{sc}">{d.score}</span></td>'
                f'<td class="ctr small">{raw_display}{amp_note}</td>'
                f'<td class="small">{findings}</td>'
                '</tr>'
            )
        body = (
            '<table class="data">'
            '<thead><tr><th>维度</th><th>权重</th><th>评分</th><th>原始→加权</th><th>命中点</th></tr></thead>'
            f'<tbody>{rows}</tbody></table>'
            '<div class="small muted" style="margin-top:4px;">* 表示经过放大系数调整；原始分 = 实际命中分数，加权分 = 原始分 × 系数</div>'
        )
        if result.correlation_bonus:
            bd_detail = result.score_breakdown.correlation_bonus_detail if result.score_breakdown else ""
            reason_note = f'（{bd_detail}）' if bd_detail else ""
            body += (
                f'<div class="corr-line">跨维度关联加分：+{result.correlation_bonus} {reason_note}'
                '　<span class="muted">（多个维度同时命中高危时叠加，可能性更高）</span></div>'
            )
        return self._detail("📋 各维度评分汇总", body)

    def _gen_detail_headers(self, meta) -> str:
        if not meta or not meta.headers:
            return self._detail("📎 附录：完整邮件头", '<p class="empty">无邮件头信息。</p>')
        headers = meta.headers
        if len(headers) > 5000:
            headers = headers[:5000] + "\n[... 已截断 ...]"
        return f"""
  <details class="det">
    <summary>📎 附录：完整邮件头</summary>
    <div class="det-body"><pre class="raw-headers">{self._e(headers)}</pre></div>
  </details>"""

    # =========================================================
    # 页脚
    # =========================================================
    def _gen_footer(self) -> str:
        return """
<!-- 页脚 -->
<div class="foot">
  <div>报告由 PhishGuard 钓鱼邮件检测智能体自动生成，仅供参考，不能完全代替人工判断。</div>
  <div class="muted">第①层是结论建议，第②层是大白话问题清单，第③层是技术细节。</div>
</div>"""

    # =========================================================
    # CSS（浅色、打印友好）
    # =========================================================
    def _get_css(self) -> str:
        return """
        * { margin:0; padding:0; box-sizing:border-box; }
        :root { --line:#e2e8f0; --ink:#0f172a; --muted:#64748b; --bg:#f8fafc; --card:#ffffff; }
        body { font-family:'Segoe UI','Microsoft YaHei',system-ui,sans-serif; background:var(--bg); color:var(--ink); line-height:1.65; }
        .report { max-width:920px; margin:24px auto; padding:0 16px 60px; }

        /* 报告头 */
        .doc-head { background:var(--card); border:1px solid var(--line); border-radius:14px; padding:22px 24px; box-shadow:0 6px 20px -12px rgba(15,23,42,.18); }
        .doc-head-top { display:flex; justify-content:space-between; align-items:flex-start; gap:16px; flex-wrap:wrap; margin-bottom:18px; }
        .kicker { font-size:13px; color:var(--muted); letter-spacing:.04em; }
        .filename { font-size:16px; font-weight:700; margin-top:4px; word-break:break-all; }
        .meta-line { font-size:12px; color:var(--muted); margin-top:6px; word-break:break-all; }
        .doc-actions { display:flex; align-items:center; gap:8px; }
        .btn-print { background:#0ea5e9; color:#fff; border:none; padding:7px 14px; border-radius:8px; font-size:13px; cursor:pointer; }
        .btn-print:hover { background:#0284c7; }

        .score-strip { display:flex; align-items:center; gap:20px; background:#f1f5f9; border-radius:12px; padding:18px; }
        .score-circle { width:96px; height:96px; border-radius:50%; border:6px solid; display:flex; flex-direction:column; align-items:center; justify-content:center; flex-shrink:0; background:#fff; }
        .score-num { font-size:32px; font-weight:800; line-height:1; }
        .score-unit { font-size:12px; color:var(--muted); }
        .score-side { flex:1; }
        .risk-pill { display:inline-block; color:#fff; font-weight:700; font-size:14px; padding:5px 14px; border-radius:999px; margin-bottom:8px; }
        .risk-scale { display:flex; gap:6px; margin-bottom:10px; flex-wrap:wrap; }
        .risk-scale .seg { font-size:12px; padding:3px 8px; border-radius:6px; background:#e2e8f0; color:#475569; }
        .risk-scale .seg.on { background:#334155; color:#fff; }

        /* 层 */
        .layer { background:var(--card); border:1px solid var(--line); border-radius:14px; padding:20px 22px; margin-top:16px; box-shadow:0 4px 16px -10px rgba(15,23,42,.16); }
        .layer-h { font-size:17px; font-weight:700; margin-bottom:10px; padding-bottom:8px; border-bottom:1px solid var(--line); }
        .layer-note { font-size:13px; color:var(--muted); margin-bottom:14px; }
        .legend { margin-left:8px; font-size:12px; color:#475569; }
        .dot-inline { display:inline-block; width:8px; height:8px; border-radius:50%; margin-right:5px; vertical-align:middle; }
        .dot-safe{ background:#10b981; } .dot-warn{ background:#f59e0b; } .dot-danger{ background:#ef4444; }

        /* 第1层 */
        .verdict { margin:4px 0 10px; }
        .verdict-big { font-size:20px; font-weight:800; }
        .why { font-size:14px; background:#f1f5f9; padding:10px 14px; border-radius:10px; margin-bottom:12px; color:#334155; }
        .why-k { font-weight:700; color:#0f172a; }
        .advice { background:#eff6ff; border:1px solid #bfdbfe; border-radius:10px; padding:12px 16px; }
        .advice-h { font-weight:700; margin-bottom:6px; color:#1d4ed8; }
        .advice-list { margin:0; padding-left:22px; }
        .advice-list li { font-size:14px; margin-bottom:6px; color:#1e3a8a; }

        /* 得分瀑布 */
        .wf-container { background:#f8fafc; border:1px solid var(--line); border-radius:10px; padding:12px 14px; margin-bottom:12px; }
        .wf-hint { font-size:12px; color:var(--muted); margin-bottom:8px; font-weight:600; }
        .wf-row { display:flex; align-items:center; gap:8px; margin-bottom:6px; font-size:13px; }
        .wf-label { width:72px; flex-shrink:0; color:#334155; font-weight:500; }
        .wf-bar-bg { flex:1; height:8px; background:#e2e8f0; border-radius:4px; overflow:hidden; }
        .wf-bar-fill { height:100%; border-radius:4px; background:linear-gradient(90deg,#7c3aed,#2563eb); transition:width .6s ease; }
        .wf-corr-fill { background:linear-gradient(90deg,#a855f7,#9333ea); }
        .wf-score { width:36px; text-align:right; color:#7c3aed; font-weight:700; font-size:12px; }
        .wf-corr .wf-label { color:#7c3aed; }

        /* 第2层 问题块 */
        .issue-block { border:1px solid var(--line); border-radius:10px; padding:14px 16px; margin-bottom:12px; }
        .issue-block-h { display:flex; justify-content:space-between; align-items:center; margin-bottom:10px; }
        .ibi-title { font-weight:700; font-size:15px; }
        .ibi-score { font-size:12px; font-weight:700; }
        .badge { display:inline-block; padding:2px 9px; border-radius:999px; font-weight:700; }
        .issue { display:flex; align-items:flex-start; gap:8px; padding:8px 10px; border-radius:8px; background:#f8fafc; margin-bottom:6px; font-size:14px; }
        .issue i { margin-top:6px; flex-shrink:0; }
        .prose { font-size:14px; color:#334155; margin-bottom:8px; background:#f8fafc; padding:10px 12px; border-radius:8px; }
        .empty { color:var(--muted); font-size:13px; padding:6px 0; }

        /* 第3层 折叠 */
        details.det { border:1px solid var(--line); border-radius:10px; padding:0; margin-bottom:10px; background:#f8fafc; }
        details.det > summary { cursor:pointer; padding:12px 16px; font-weight:600; font-size:14px; list-style:none; }
        details.det > summary::-webkit-details-marker { display:none; }
        details.det > summary::before { content:"▶"; display:inline-block; margin-right:8px; font-size:10px; color:#94a3b8; transition:transform .15s; }
        details.det[open] > summary::before { transform:rotate(90deg); }
        .det-body { padding:0 16px 14px 16px; }
        .term-hint { font-size:12px; color:#475569; background:#eef2ff; border-radius:8px; padding:8px 12px; margin-bottom:10px; line-height:1.7; }

        /* 表格 */
        table.kv { width:100%; border-collapse:collapse; font-size:13px; }
        table.kv td { padding:7px 10px; border-bottom:1px solid var(--line); }
        table.kv .k { color:var(--muted); width:200px; white-space:nowrap; }
        table.data { width:100%; border-collapse:collapse; font-size:12.5px; margin-top:6px; }
        table.data th { background:#f1f5f9; color:#334155; text-align:left; padding:9px 8px; font-weight:600; border-bottom:1px solid var(--line); }
        table.data td { padding:8px; border-bottom:1px solid var(--line); vertical-align:top; }
        table.data tr:nth-child(even) td { background:#f8fafc; }
        .ctr { text-align:center; }
        .small { font-size:12px; }
        .mono { font-family:'Cascadia Code',Consolas,monospace; }
        .break { word-break:break-all; }

        .tag { display:inline-block; padding:2px 8px; border-radius:6px; font-size:12px; font-weight:600; }
        .tag-ok { background:#dcfce7; color:#15803d; } .tag-warn { background:#fef3c7; color:#b45309; }
        .tag-bad { background:#fee2e2; color:#b91c1c; } .tag-muted { background:#e2e8f0; color:#475569; }

        .findings { padding-left:20px; margin:8px 0; }
        .findings li { font-size:13px; color:#334155; margin-bottom:4px; }

        .cbars { display:flex; flex-direction:column; gap:7px; margin:8px 0; }
        .cbar-row { display:flex; align-items:center; gap:10px; font-size:13px; }
        .cbar-k { width:90px; color:#475569; }
        .cbar { flex:1; background:#e2e8f0; height:9px; border-radius:5px; overflow:hidden; }
        .cbar-fill { height:100%; border-radius:5px; }
        .corr-line { font-size:13px; margin-top:10px; padding:8px 12px; background:#faf5ff; border-radius:8px; color:#6b21a8; }
        .muted { color:var(--muted); }

        .raw-headers { background:#0f172a; color:#e2e8f0; padding:14px; border-radius:8px; font-size:11.5px; overflow-x:auto; max-height:360px; overflow-y:auto; white-space:pre-wrap; word-break:break-all; font-family:Consolas,monospace; }
        a { color:#0ea5e9; }

        .foot { text-align:center; font-size:12px; color:var(--muted); margin-top:24px; line-height:1.8; }

        @media print {
          body { background:#fff; }
          .report { max-width:none; margin:0; padding:0 8px; }
          .doc-head,.layer { box-shadow:none; border:1px solid #ccc; }
          .no-print { display:none !important; }
          details.det { background:#fff !important; }
          details.det:not([open]) > .det-body { display:block !important; }
          details.det > summary::before { content:""; }
          .raw-headers { background:#f1f5f9; color:#0f172a; }
        }
        """