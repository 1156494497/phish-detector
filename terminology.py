"""
大白话翻译模块

把检测引擎输出的专业术语和 findings 翻译成普通人能看懂的语言。
分四部分：
  1. translate_finding(text)      —— 正则表把单条专业 finding 翻成大白话（兜底）
  2. GLOSSARY                     —— 给"技术细节"区里出现的术语配一句话说明
  3. build_action_list(result)    —— 根据风险情况给出"你该怎么办"行动清单
  4. FindingsTranslator 类        —— 用 LLM 批量把 findings 改写为大白话，
                                     LLM 不可用时自动退化到正则兜底；带内存缓存。

匹配原则：正则兜底用关键词子串匹配，命中即翻译；未命中则原样返回（不强翻，避免出错）。
LLM 原则：一次请求把整封邮件的全部 findings 一起丢给模型改写，省调用；按 JSON 取回。
"""
import json
import logging
import re
from typing import Optional

from models import DetectionResult, RiskLevel

logger = logging.getLogger(__name__)


# ============================================================
# 术语词汇表：术语 -> 一句话解释（用在技术细节区做注释）
# ============================================================
GLOSSARY = {
    "SPF": "SPF：相当于发件域名的“授权名单”，标明哪些服务器有权用它发信。通过=可信；失败=这封可能是冒充的。",
    "DKIM": "DKIM：邮件的“数字签名”，能证明邮件中途没被篡改。通过=真实；失败=可能被伪造或篡改。",
    "DMARC": "DMARC：域名对所有者定的“收信规则”，告诉收件方该怎样处理 SPF/DKIM 不通过的邮件。",
    "Reply-To": "Reply-To：你点“回复”时邮件发往的真实地址。如果它和发件人地址不一致，骗子常用这招接收回信。",
    "Return-Path": "Return-Path：退信会发往的地址。与发件人不一致时，常常是伪造发件人的迹象。",
    "VBA宏": "VBA 宏：Office 文档里的小程序。正常文档里一般没有，攻击者常用它来藏病毒。",
    "SHA256": "SHA256：文件的“数字指纹”，全世界唯一。可用来在 VirusTotal 等平台查这个文件是否被报过毒。",
    "VirusTotal": "VirusTotal：一个把几十款杀毒引擎凑在一起同时查毒的免费网站。",
    "VBA": "VBA 宏：Office 文档里的小程序。正常文档里一般没有，攻击者常用它来藏病毒。",
    "HTTPS": "HTTPS：加密的网页连接。如果链接是 http（没加 s），数据可能在路上被看到或篡改。",
    "HSTS": "HSTS：浏览器强制走 HTTPS 的安全策略。",
    "短链接": "短链接：把长网址缩短的服务。背后真实地址被隐藏，常被用来骗点击。",
    "追踪像素": "追踪像素：邮件里藏的一个 1 像素小图片，用来偷偷记录你有没有打开邮件、在哪打开的。",
    "HTML表单": "HTML 表单：网页上让你填账号密码的格子。邮件里直接放表单通常是钓鱼套路。",
    "隐藏元素": "隐藏元素：网页里写了对人眼不可见的内容，常被用来骗过过滤系统或藏关键字。",
    "顶级域": "顶级域（TLD）：域名的最后一段，如 .com、.cn。一些很冷门的 TLD 常被钓鱼邮件利用。",
}


# ============================================================
# translation rule table
# 规则表： (关键字/正则, 大白话模板 Placeholders 用 regex groups)
# 顺序敏感，先匹配先返回
# ============================================================
# Each rule: (compiled_pattern, replacement_template)
# replacement is plain string; capture groups inserted via .group(1)/...
_RAW_RULES = [
    # —— 链接类 ——
    (r"href_mismatch|显示文本.*?不一致|显示文本与实际域名不一致", "链接上的文字看起来是正常网站，但点进去其实会跳到另一个域名 —— 这是钓鱼最常见的套路。"),
    (r"URL 使用 IP 地址代替域名[:：]\s*(.*)", r"链接里没用域名，直接用一串数字地址（IP：\1），这种写法正常网站几乎不会用，风险很高。"),
    (r"URL 中包含 @ 符号", "链接里藏了 @ 符号，@ 后面的内容浏览器才会真正访问，前面的是用来骗你看的。"),
    (r"URL 未使用 HTTPS 加密连接", "这个链接是 http（没加密）而不是 https，数据在传输中可能被看到或篡改。"),
    (r"域名注册仅 (\d+) 天.*?(< 30天).*?极高风险", r"这个网址是才注册 \1 天的新域名——骗子常临时申请新域名作案，风险很高。"),
    (r"域名注册 (\d+) 天.*?(< 90天).*?中等风险", r"这个网址比较新（注册 \1 天），建议多留个心眼。"),
    (r"域名注册 (\d+) 天.*?(< 180天).*?需关注", r"这个网址不算老（注册 \1 天），可以稍加留意。"),
    (r"疑似仿冒品牌域名[:：]\s*(.*?) → 可能冒充 (.*)", r"网址 \1 看着像正规公司，其实在仿冒 \2——名字拼得很像，目的是骗你信以为真。"),
    (r"URL 使用短链接服务[:：]\s*(.*)", r"这是个短链接（\1）。它把真实地址藏起来了，你点之前根本不知道会跳到哪里。"),
    (r"短链接重定向到不同域名[:：]\s*(.*)", r"短链接最终跳到了另一个域名：\1。中途偷换地址是钓鱼的典型做法。"),
    (r"URL 托管在免费平台[:：]\s*(.*)", r"这个链接放在免费建站平台（\1）上——正规公司的官方链接一般不会用这种免费空间。"),
    (r"URL 中包含可疑关键词[:：]\s*(.*)", r"链接里出现了一些可疑字眼：\1。"),
    (r"URL 包含过多子域名层级[:：]\s*(.*)", r"这个网址前面的层级特别多（\1），像把正规公司名塞在一长串里来骗你。"),
    (r"域名异常过长\s*\((\d+) 字符\)", r"这个域名异常长（\1 个字符），像是为了塞进关键字来骗人和过滤系统。"),
    (r"VirusTotal[:：]\s*(\d+)/(\d+) 引擎判定为恶意", r"在 VirusTotal 上有 \1 款杀毒引擎把它判为恶意——已经有不少安全软件认定它有问题。"),
    (r"VirusTotal 声誉分[:：]\s*(\d+) ?\(负面\)", r"VirusTotal 给这个域名打了一个偏负面的信誉分（\1），被不少人标记过。"),
    (r"VT 分类[:：]\s*(.*)", r"VirusTotal 把它归类为：\1。"),

    # —— 附件类 ——
    (r"双重扩展名检测[:：]\s*(.*?) — 可能伪装文件类型", r"附件名 \1 有两个后缀（比如 .pdf.exe），目的是伪装成文档类型骗你双击打开。"),
    (r"高危文件类型[:：]\s*(\.\S+) \((.*)\)", r"附件 \2 是高危类型（\1），这种格式的文件天生容易藏病毒，谨慎打开。"),
    (r"中危文件类型[:：]\s*(\.\S+)，需进一步检测宏", r"附件类型（\1）属于中危，要再确认里面有没有藏“宏”这种小程序。"),
    (r"未知文件类型[:：]\s*(\.\S+) \((.*)\)", r"附件 \2 用了一个不常见的后缀（\1），常规软件打不开，需要警惕。"),
    (r"文件类型伪装[:：]\s*扩展名为 (.*?)，?但实际类型为 (.*)", r"文件后缀看着是 \1，实际内容是 \2——冒充文件类型是典型套路。"),
    (r"压缩包已加密（密码保护），无法检查内部内容.*?:\s*(.*)", r"\1 是个加了密码的压缩包，安全软件看不到里面装了什么——这种做法常用来躲过扫描，风险很高。"),
    (r"压缩包内含高危文件[:：]\s*(.*)", r"压缩包里塞了高危文件：\1。"),
    (r"检测到恶意宏，包含可疑关键字[:：]\s*(.*)", r"文档里藏着带可疑关键字的“宏”（\1），打开就可能让攻击者控制你的电脑。"),
    (r"文档包含 VBA 宏（未发现明显恶意行为）", "文档里有 VBA 宏这种小程序。虽然没发现明显恶意，但正常文档通常不需要宏，建议谨慎。"),
    (r"附件为空文件[:：]\s*(.*)", r"附件 \1 是空的，像是在探测你会不会下载，可能配合后续钓鱼。"),
    (r"附件体积异常[:：]\s*([0-9.]+)MB", r"附件个头异常大（\1 MB），有点不寻常。"),

    # —— 发件人 / 认证 ——
    (r"发件人显示名包含 '.*?' 但邮箱域名不匹配[:：]\s*(.*)", r"发件人名字像某公司，但邮箱域名跟它对不上（\1）——多半是冒充的。"),
    (r"发件人显示名 '.*?' 与邮箱地址 '.*?' 不一致", "发件人显示的名字和真实邮箱地址对不上，常见于冒充邮件。"),
    (r"发件人使用免费邮箱[:：]\s*(.*)", r"发件人用的是免费邮箱（\1）。如果对方自称是公司/机构却用免费邮箱，基本不可信。"),
    (r"发件人域名使用可疑顶级域[:：]\s*(.*)", r"发件域名的后缀比较可疑（\1），这类很冷门的“顶级域”常被钓鱼邮件利用。"),
    (r"发件人地址为空", "邮件里没写发件人地址，正常邮件几乎不会这样。"),
    (r"SPF 验证失败 — 发件人服务器未被授权发送此邮件", "SPF 验证没过：发信的服务器其实没被授权以这个域名发信——很可能是冒充的。"),
    (r"SPF 软失败 — 发件人服务器可能未授权", "SPF 软失败：发信的服务器可能没被授权，需要重点怀疑。"),
    (r"SPF 验证通过", "SPF 验证通过：发信服务器是被授权的（这是好事，但不能单独证明安全）。"),
    (r"SPF 未配置 — 域名未设置 SPF 记录", "发件域名连 SPF 记录都没设，正规机构一般会配置。"),
    (r"DKIM 验证失败 — 邮件签名无效或被篡改", "DKIM 验证没过：邮件签名无效或途中被改过。"),
    (r"DKIM 验证通过", "DKIM 验证通过：邮件有合法数字签名。"),
    (r"DKIM 未配置 — 域名未设置 DKIM 签名", "发件域名没有 DKIM 签名。"),
    (r"DMARC 验证失败 — 邮件未通过域名对齐策略", "DMARC 验证没过：这封邮件没通过该域名的收信策略，可信度低。"),
    (r"DMARC 验证通过", "DMARC 验证通过。"),
    (r"DMARC 未配置", "发件域名没配置 DMARC 策略。"),
    (r"Reply-To 地址与 From 地址不一致", "你点“回复”时，回信会发到另一个地址（和发件人不一样）——骗子常用这招收你的回信。"),
    (r"Return-Path 地址与 From 地址不一致 — 可能伪造发件人", "退信地址和发件人不一样，可能是伪造的来源。"),

    # —— 内容 ——
    (r"(.*)[:：]发现关键词 (.*)", r"\1：里面出现了这类关键字 \2——是常见骗术话术。"),

    # —— HTML 结构 ——
    (r"检测到 (\d+) 个 HTML 表单.*?含 (\d+) 个密码输入框", r"邮件里藏了 \1 个让你填账号密码的页面（含 \2 个密码框）——正规通知一般不会让在邮件里直接填密码。"),
    (r"检测到 (\d+) 个 HTML 表单$", r"邮件里藏了 \1 个让你填信息的页面（HTML 表单），钓鱼常用。"),
    (r"检测到 (\d+) 个追踪像素", r"邮件里藏了 \1 个你看不见的“追踪像素”，用来偷偷记录你打开邮件的时间和地点。"),
    (r"检测到 (\d+) 个隐藏元素", r"邮件里有 \1 处对你眼睛不可见的内容——常用来骗过过滤系统或藏关键字。"),

    # —— 新增：假登录框 & 深度 JS ——
    (r"检测到假登录框：疑似仿冒 (\w+) 登录界面", r"邮件里有假登录框——页面看着像 \1 的官方登录页，其实是钓鱼陷阱，输入账号密码就直接被盗。"),
    (r"检测到数据外传行为：向 (.*?) 等外部地址发送数据", r"页面里有代码会偷偷把你在表单里填的内容发到外部服务器（\1），属于数据窃取行为。"),
    (r"发现 (\d+) 个隐藏 URL", r"邮件里隐藏了 \1 个不在明处的 URL，可能是用 base64 编码藏起来的钓鱼跳转目标。"),
    (r"检测到反分析代码.*禁用右键.*F12.*开发者工具.*", "页面有代码在阻止你用右键菜单或打开开发者工具——这是在防止你看到它背后的真实行为。"),
    (r"检测到反机器人检测代码.*WebDriver.*Puppeteer.*Selenium.*", "页面有代码在检测你是否在使用自动化工具（机器人），这通常说明它不想被安全扫描器发现。"),

    # —— 新增：攻击类型大白话 ——
    (r"凭据钓鱼（假登录页）", "这封邮件在试图让你到一个假登录页输入账号密码，账号会被直接盗走。"),
    (r"OAuth授权劫持.*凭证窃取|OAuth授权劫持", "邮件诱导你授权某个应用访问 Google/Microsoft 账号——授权后攻击者可在不知情的情况下操控你的账户，风险极高。"),

    # —— 兜底通用 ——
    (r"VirusTotal[:：]\s*(\d+)/(\d+) 引擎.*安全", r"在 VirusTotal 上 \1/\2 款杀毒引擎都判定为安全。"),
    (r"VT[:：]? ?文件未被收录（可能是新文件）", "VirusTotal 上没查到这个文件，可能是很新的文件，参考价值有限。"),
    (r"VT查询超时|VT查询失败|VT查询异常", "VirusTotal 查询没成功（超时或出错），这次没有杀毒引擎的参考。"),
]

# 编译并保留原始字符串
_COMPILED_RULES = [(re.compile(p, re.IGNORECASE), t) for p, t in _RAW_RULES]


def translate_finding(text: str) -> str:
    """
    把一条专业 finding 翻译成大白话。
    匹配不到就原样返回（不强行翻译，避免误导）。
    """
    if not text:
        return text
    for pat, tmpl in _COMPILED_RULES:
        m = pat.search(text)
        if m:
            # 把模板里的 \1 \2 这种反向引用替换成 groups
            try:
                return m.expand(tmpl)
            except re.error:
                return tmpl
    return text


def glossary_hint(term: str) -> str:
    """返回术语的一句话解释，找不到返回空串"""
    if not term:
        return ""
    # 精确匹配优先，再尝试包含
    if term in GLOSSARY:
        return GLOSSARY[term]
    for k, v in GLOSSARY.items():
        if k in term or term in k:
            return v
    return ""


# ============================================================
# “你该怎么办” 行动清单 —— 根据风险等级和命中维度给出建议
# ============================================================
def build_action_list(result: DetectionResult) -> list[str]:
    """根据检测结果生成普通人能照做的行动清单（<=4 条）"""
    actions: list[str] = []
    level = result.risk_level

    if level == RiskLevel.SAFE:
        actions.append("这封邮件整体没有明显风险，但若涉及账号/付款，仍建议通过官方渠道二次确认。")
        return actions

    # 高危：最重要的几条
    if level == RiskLevel.MALICIOUS:
        # OAuth 劫持专项警告
        content = result.content_analysis
        oauth = content and getattr(content, "oauth_hijack_detected", False)
        if oauth:
            domain = getattr(content, "oauth_hijack_domain", "") if content else ""
            extra = f" 请勿点击任何授权链接（域名 {domain}）。" if domain else ""
            actions.append("这封邮件在诱导你授权第三方应用访问 Google/Microsoft 等账号——授权后攻击者可在后台长期监控你的邮件和联系人。" + extra)
        actions.append("先别点任何链接，也别打开、也别下载任何附件。")
        actions.append("把邮件删掉或报告给你单位的邮箱管理员/安全团队。")
        actions.append("如果已经点过链接或开过附件，立即断网、改相关账号密码并联系安全人员。")
        return actions

    # 可疑
    actions.append("不要在邮件里填写账号、密码、验证码或付款信息。")
    # 根据命中维度细补
    has_url = result.url_analysis and result.url_analysis.max_score > 30
    has_att = result.attachment_analysis and result.attachment_analysis.max_score > 30
    if has_url:
        actions.append("链接先别点；如果想确认，直接去官方网站或 App 里操作，而不是走邮件里的链接。")
    if has_att:
        actions.append("附件先别打开；如确需查看，先在隔离环境/查毒平台扫一遍再用。")
    from_en_analysis = result.sender_analysis and result.sender_analysis.score > 30
    if from_en_analysis:
        actions.append("对发件人事先不通和你商量、却来催你办事的，打电话或当面跟本人确认。")
    actions.append("拿不准就先放着，问一下身边的 IT 或安全人员再决定。")
    # 截断到 4 条
    return actions[:4]


# ============================================================
# 一句话结论：根据等级和主因给出最顶部的“一句话为什么”
# ============================================================
def one_line_reason(result: DetectionResult) -> str:
    """给最顶部结论栏用的一句话大白话原因"""
    reasons = []

    # OAuth 劫持 → 最高优先级
    content = result.content_analysis
    if content and getattr(content, "oauth_hijack_detected", False):
        reasons.append("邮件在诱导你授权第三方应用访问你的账号，风险极高")

    if result.url_analysis and result.url_analysis.max_score > 60:
        reasons.append("邮件里的链接很可疑")
    if result.attachment_analysis and result.attachment_analysis.max_score > 60:
        reasons.append("附件有明显的危险特征")
    if result.content_analysis and result.content_analysis.score > 60:
        reasons.append("正文话术像在骗人")
    if result.sender_analysis and result.sender_analysis.score > 60:
        reasons.append("发件人来路不正")
    # 假登录框
    if result.html_analysis and result.html_analysis.has_fake_login_page:
        reasons.append("有假登录框陷阱")

    if reasons:
        return "、".join(reasons)
    if result.risk_level == RiskLevel.MALICIOUS:
        return "多个地方同时踩雷，基本可认定为钓鱼邮件"
    if result.risk_level == RiskLevel.SUSPICIOUS:
        return "有些地方不太对劲，需要你留个心眼"
    return "没有发现明显可疑的地方"


# ============================================================
# FindingsTranslator —— 用 LLM 把一封邮件的全部 findings 批量改写为大白话
# LLM 不可用 → 自动退化到正则 translate_finding。
# 设计：一次请求改写一个 detection_result 的所有 findings，按 JSON 取回；
#       结果按原文哈希缓存（同一句话不重复请求）。
# ============================================================
from config import (
    LLM_MODEL, LLM_TEMPERATURE, LLM_MAX_TOKENS,
)


class FindingsTranslator:
    """findings → 大白话，LLM 优先，正则兜底"""

    def __init__(self, llm_client=None):
        """
        llm_client: 复用 content_analyzer.llm_client（同进程同模型）；为 None 则只走正则。
        你不需要自己造 client，传 app 里的 content_analyzer.llm_client 即可。
        """
        self.llm_client = llm_client
        self._cache: dict[str, str] = {}  # 原文 -> 大白话（同进程内复用）

    # 把一封邮件的所有 findings 收集成 [(原文)] 顺序，并记住每条出自哪个维度
    @staticmethod
    def _collect_findings(result: DetectionResult) -> list[tuple[str, str]]:
        """返回 [(维度名, finding原文), ...]"""
        items: list[tuple[str, str]] = []
        if result.url_analysis:
            for f in result.url_analysis.findings or []:
                items.append(("链接", f))
        if result.attachment_analysis:
            for f in result.attachment_analysis.findings or []:
                items.append(("附件", f))
        if result.content_analysis:
            for f in result.content_analysis.suspicious_indicators or []:
                items.append(("内容", f))
        if result.sender_analysis:
            for f in result.sender_analysis.findings or []:
                items.append(("发件人", f))
        if result.html_analysis:
            for f in result.html_analysis.findings or []:
                items.append(("HTML结构", f))
        return items

    def translate_all(self, result: DetectionResult) -> dict[str, str]:
        """
        翻译一封邮件的全部 findings。
        返回 {finding原文: 大白话}。LLM 失败则该条用正则 translate_finding 兜底。
        """
        items = self._collect_findings(result)
        if not items:
            return {}

        # 去重，先抽缓存
        out: dict[str, str] = {}
        todo: list[tuple[str, str]] = []
        for dim, text in items:
            if text in self._cache:
                out[text] = self._cache[text]
            else:
                todo.append((dim, text))
        if not todo:
            return out

        # 没有 LLM 直接收口到正则
        if not self.llm_client:
            for dim, text in todo:
                t = translate_finding(text)
                self._cache[text] = t
                out[text] = t
            return out

        # 有 LLM：批量改写
        llm_map = self._rewrite_batch(todo)
        for dim, text in todo:
            t = llm_map.get(text)
            # LLM 没给 / 给得不合理 → 兜底正则
            if not t or len(t) > 120 or t == text:
                t = translate_finding(text)
            self._cache[text] = t
            out[text] = t
        return out

    def _rewrite_batch(self, items: list[tuple[str, str]]) -> dict[str, str]:
        """用 LLM 把多条 findings 一次改写，返回 {原文: 大白话}"""
        import hashlib
        # 给每条一个稳定编号，要求模型按编号回 JSON
        numbered = []
        for i, (dim, text) in enumerate(items):
            numbered.append({"id": i, "src": text})

        prompt = (
            "你是安全科普翻译员。下面是一封邮件检测结果中的若干条「可疑点」原始描述"
            "（含专业术语），请把每一条改写成普通人能看懂的一句话大白话：\n"
            "要求：\n"
            "1) 用生活语言，不超过 80 个字，不要列点；\n"
            "2) 保留关键事实（域名/文件名/数量/SPF 等结果），但用人话解释为什么危险；\n"
            "3) 不要复读术语，要让小白明白风险点；\n"
            "4) 只输出 JSON 数组，每个元素 {\"id\": 原编号, \"plain\": 大白话}，不要输出任何额外文字。\n"
            f"输入：\n{json.dumps(numbered, ensure_ascii=False)}"
        )

        try:
            resp = self.llm_client.chat.completions.create(
                model=LLM_MODEL,
                messages=[
                    {"role": "system", "content": "你是安全科普翻译助手，只输出JSON。"},
                    {"role": "user", "content": prompt},
                ],
                temperature=LLM_TEMPERATURE,
                max_tokens=LLM_MAX_TOKENS,
            )
            content = resp.choices[0].message.content.strip()
            # 兼容模型偶尔包 ```json 代码块
            if content.startswith("```"):
                content = content.strip("`")
                if content.lower().startswith("json"):
                    content = content[4:].strip()
            arr = json.loads(content)
            result: dict[str, str] = {}
            for i, (dim, text) in enumerate(items):
                for item in arr:
                    if isinstance(item, dict) and item.get("id") == i and item.get("plain"):
                        result[text] = str(item["plain"]).strip()
                        break
            return result
        except Exception as e:
            logger.warning(f"FindingsTranslator LLM 批改写失败，退化正则兜底: {e}")
            return {}