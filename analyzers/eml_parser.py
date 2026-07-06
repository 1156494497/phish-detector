"""
EML 文件解析器
从 .eml 文件（RFC 2822 标准邮件格式）中提取邮件元数据、正文、URL、附件
"""
import re
import email
import hashlib
import logging
from email import policy
from email.parser import BytesParser
from email.header import decode_header
from urllib.parse import urlparse, unquote
from bs4 import BeautifulSoup

from models import ParsedEmail, EmailMetadata, AttachmentInfo, HtmlAnalysisResult

logger = logging.getLogger(__name__)

# URL 提取正则
URL_PATTERN = re.compile(
    r'https?://[^\s<>"\'\)\]\\]+',
    re.IGNORECASE
)

HREF_PATTERN = re.compile(
    r'href=["\']([^"\']+)["\']',
    re.IGNORECASE
)


class EmlParser:
    """解析 .eml 文件，提取结构化邮件数据"""

    def parse(self, data: bytes) -> tuple[ParsedEmail, dict[str, bytes]]:
        """
        解析 .eml 文件二进制数据

        Args:
            data: .eml 文件二进制内容

        Returns:
            (parsed_email, attachment_data_map)
        """
        msg = BytesParser(policy=policy.default).parsebytes(data)

        metadata = self._extract_metadata(msg)
        body_text, body_html = self._extract_body(msg)
        urls, url_display_map = self._extract_urls(body_text, body_html)
        attachments, attachment_data = self._extract_attachments(msg)

        metadata.url_count = len(urls)
        metadata.attachment_count = len(attachments)
        metadata.has_html = bool(body_html)

        parsed = ParsedEmail(
            metadata=metadata,
            body_text=body_text,
            body_html=body_html,
            urls=urls,
            url_display_map=url_display_map,
            attachments=attachments,
        )

        return parsed, attachment_data

    def _decode_header_value(self, value: str) -> str:
        """解码邮件头中的编码值"""
        if not value:
            return ""
        try:
            decoded_parts = decode_header(value)
            result = []
            for part, charset in decoded_parts:
                if isinstance(part, bytes):
                    result.append(part.decode(charset or "utf-8", errors="ignore"))
                else:
                    result.append(part)
            return "".join(result)
        except Exception:
            return str(value)

    def _extract_metadata(self, msg) -> EmailMetadata:
        """提取邮件元数据"""
        # 发件人
        from_header = self._decode_header_value(str(msg.get("From", "")))
        sender_name = ""
        sender_email = ""

        # 解析发件人（格式: "Name <email>" 或纯 email）
        if "<" in from_header and ">" in from_header:
            match = re.match(r'^(.+?)\s*<(.+?)>', from_header)
            if match:
                sender_name = match.group(1).strip().strip('"')
                sender_email = match.group(2).strip()
            else:
                sender_email = from_header.strip()
        else:
            sender_email = from_header.strip()

        # 发件人域名
        sender_domain = ""
        if "@" in sender_email:
            sender_domain = sender_email.split("@")[-1].lower().strip(">")

        # 收件人
        to_list = []
        to_header = msg.get("To", "")
        if to_header:
            to_str = self._decode_header_value(str(to_header))
            to_list = [addr.strip() for addr in to_str.split(",") if addr.strip()]

        cc_list = []
        cc_header = msg.get("Cc", "")
        if cc_header:
            cc_str = self._decode_header_value(str(cc_header))
            cc_list = [addr.strip() for addr in cc_str.split(",") if addr.strip()]

        # 主题
        subject = self._decode_header_value(str(msg.get("Subject", "")))

        # 日期
        date_str = str(msg.get("Date", ""))

        # Message-ID
        message_id = str(msg.get("Message-ID", ""))

        # 邮件头（完整）
        headers = ""
        try:
            header_lines = []
            for key in msg.keys():
                header_lines.append(f"{key}: {msg[key]}")
            headers = "\n".join(header_lines)
        except Exception:
            pass

        return EmailMetadata(
            sender_name=sender_name,
            sender_email=sender_email,
            sender_domain=sender_domain,
            to=to_list,
            cc=cc_list,
            subject=subject,
            date=date_str,
            message_id=message_id,
            headers=headers,
        )

    def _extract_body(self, msg) -> tuple[str, str]:
        """提取邮件正文（纯文本 + HTML）"""
        body_text = ""
        body_html = ""

        try:
            if msg.is_multipart():
                for part in msg.walk():
                    content_type = part.get_content_type()
                    disposition = str(part.get("Content-Disposition", ""))

                    # 跳过附件
                    if "attachment" in disposition:
                        continue

                    if content_type == "text/plain" and not body_text:
                        payload = part.get_content()
                        if isinstance(payload, bytes):
                            charset = part.get_content_charset() or "utf-8"
                            payload = payload.decode(charset, errors="ignore")
                        body_text = payload
                    elif content_type == "text/html" and not body_html:
                        payload = part.get_content()
                        if isinstance(payload, bytes):
                            charset = part.get_content_charset() or "utf-8"
                            payload = payload.decode(charset, errors="ignore")
                        body_html = payload
            else:
                content_type = msg.get_content_type()
                payload = msg.get_content()
                if isinstance(payload, bytes):
                    charset = msg.get_content_charset() or "utf-8"
                    payload = payload.decode(charset, errors="ignore")

                if content_type == "text/html":
                    body_html = payload
                else:
                    body_text = payload

        except Exception as e:
            logger.warning(f"提取正文失败: {e}")

        return body_text, body_html

    def _extract_urls(self, body_text: str, body_html: str) -> tuple[list[str], dict[str, str]]:
        """从正文中提取并去重 URL，同时提取显示文本"""
        urls = set()
        url_display_map = {}

        # 从 HTML 的 <a> 标签提取 href 和显示文本
        if body_html:
            try:
                soup = BeautifulSoup(body_html, "html.parser")
                for a_tag in soup.find_all("a", href=True):
                    href = a_tag["href"]
                    display = a_tag.get_text(strip=True)
                    url = self._normalize_url(href)
                    if url:
                        urls.add(url)
                        if display and url not in url_display_map:
                            url_display_map[url] = display
            except Exception as e:
                logger.warning(f"HTML <a> 标签解析失败: {e}")
                for match in HREF_PATTERN.findall(body_html):
                    url = self._normalize_url(match)
                    if url:
                        urls.add(url)

        for text in [body_text, body_html]:
            if text:
                for match in URL_PATTERN.findall(text):
                    url = self._normalize_url(match)
                    if url:
                        urls.add(url)

        return sorted(urls), url_display_map

    def _normalize_url(self, url: str) -> str:
        """规范化 URL"""
        url = unquote(url.strip())
        url = url.rstrip(".,;:!?)]}>")
        if not url or len(url) < 10:
            return ""
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            return ""
        return url

    # ============================================================
    # HTML 深度分析（邮件正文 & HTML 附件共用）
    # ============================================================
    def _extract_html_signals(self, body_html: str) -> HtmlAnalysisResult:
        """
        提取 HTML 结构信号：表单、追踪像素、隐藏文本、假登录框、深度 JS 分析。
        """
        return self._deep_html_analysis(body_html)

    def _deep_html_analysis(self, html_content: str) -> HtmlAnalysisResult:
        """
        对 HTML 内容进行深度分析，包含：
          1. 表单/追踪像素/隐藏元素（基础）
          2. 假登录框检测（仿冒 Google/Microsoft/Adobe 等）
          3. 深度 JS 分析：数据外传、base64 隐藏 URL、反分析/反机器人
        """
        if not html_content:
            return HtmlAnalysisResult()

        try:
            soup = BeautifulSoup(html_content, "html.parser")
        except Exception as e:
            logger.warning(f"HTML 结构分析失败: {e}")
            return HtmlAnalysisResult()

        findings = []
        html_lower = html_content.lower()

        # ── 1. 基础：表单检测 ──────────────────────────────
        forms = soup.find_all("form")
        form_actions = []
        form_input_fields = []
        for form in forms:
            action = form.get("action", "")
            if action:
                form_actions.append(action)
            for inp in form.find_all("input"):
                name = inp.get("name", "")
                itype = inp.get("type", "")
                if name:
                    form_input_fields.append(f"{name}({itype})" if itype else name)
                elif itype:
                    form_input_fields.append(itype)

        password_fields = [i for i in soup.find_all("input") if i.get("type", "").lower() == "password"]
        if forms:
            findings.append(f"检测到 {len(forms)} 个 HTML 表单" + (f"，含 {len(password_fields)} 个密码输入框" if password_fields else ""))

        # ── 2. 追踪像素检测 ──────────────────────────────
        tracking_pixels = []
        for img in soup.find_all("img"):
            w = img.get("width", "")
            h = img.get("height", "")
            style = (img.get("style", "") or "").lower().replace(" ", "")
            if (w in ("1", "0") and h in ("1", "0")) or "display:none" in style or "display: none" in style or "opacity:0" in style:
                src = img.get("src", "")
                if src:
                    tracking_pixels.append(src)
        if tracking_pixels:
            findings.append(f"检测到 {len(tracking_pixels)} 个追踪像素")

        # ── 3. 隐藏文本检测 ──────────────────────────────
        hidden_count = 0
        for tag in soup.find_all(style=True):
            s = tag["style"].lower().replace(" ", "")
            if "display:none" in s or "visibility:hidden" in s or "opacity:0" in s:
                hidden_count += 1
        if hidden_count:
            findings.append(f"检测到 {hidden_count} 个隐藏元素（display:none/visibility:hidden/opacity:0）")

        # ── 4. 假登录框检测 ──────────────────────────────
        has_fake_login, fake_brand = self._detect_fake_login(soup, forms, html_lower)
        if has_fake_login:
            findings.append(f"检测到假登录框：疑似仿冒 {fake_brand} 登录界面")

        # ── 5. 深度 JS 分析 ──────────────────────────────
        exfil_domains, hidden_urls = self._detect_js_exfil(soup, html_content)
        has_anti_analysis = self._detect_anti_analysis(html_lower)
        has_anti_bot = self._detect_anti_bot(html_lower)

        if exfil_domains:
            findings.append(f"检测到数据外传行为：向 {', '.join(exfil_domains[:3])} 等外部地址发送数据")
        if hidden_urls:
            findings.append(f"发现 {len(hidden_urls)} 个隐藏 URL（base64 编码或其他隐藏方式）")
        if has_anti_analysis:
            findings.append("检测到反分析代码（禁用右键/F12/开发者工具）")
        if has_anti_bot:
            findings.append("检测到反机器人检测代码（WebDriver/Puppeteer/Selenium 特征）")

        return HtmlAnalysisResult(
            has_form=len(forms) > 0,
            form_actions=form_actions,
            form_input_fields=form_input_fields,
            has_tracking_pixel=len(tracking_pixels) > 0,
            tracking_pixel_urls=tracking_pixels,
            hidden_text_count=hidden_count,
            has_fake_login_page=has_fake_login,
            fake_login_brand=fake_brand,
            has_external_data_exfil=bool(exfil_domains),
            has_hidden_base64_url=bool(hidden_urls),
            has_anti_analysis=has_anti_analysis,
            has_anti_bot=has_anti_bot,
            exfil_domains=exfil_domains,
            hidden_urls=hidden_urls,
            findings=findings,
        )

    def _detect_fake_login(self, soup: BeautifulSoup, forms: list, html_lower: str) -> tuple[bool, str]:
        """
        检测假登录框：
          1. 含 <input type=password> 或 <input type=email>
          2. 表单 action 非官方域名，或无 action
          3. 页面包含品牌标识特征
        返回 (has_fake_login, brand)
        """
        # ① 必须有密码或邮箱输入框
        password_inputs = soup.find_all("input", {"type": lambda t: t and t.lower() in ("password", "email")})
        if not password_inputs:
            return False, ""

        # ② 品牌标识检测
        brand_markers = {
            "google": ["google", "gstatic", "googlesyndication", "doubleclick", "gmail"],
            "microsoft": ["microsoft", "microsoftonline", "live.com", "outlook.com", "azure"],
            "adobe": ["adobe", "acrobat", "sign.adobe"],
            "apple": ["apple", "icloud", "appleid"],
            "amazon": ["amazon", "aws.amazon"],
            "paypal": ["paypal"],
            "facebook": ["facebook", "meta", "instagram"],
            "linkedin": ["linkedin"],
        }

        detected_brand = ""
        for brand, markers in brand_markers.items():
            if any(m in html_lower for m in markers):
                detected_brand = brand
                break
        if not detected_brand:
            detected_brand = "other"

        # ③ 表单 action 非官方域名检测
        for form in forms:
            action = form.get("action", "").strip()
            if not action:
                # 无 action 默认提交本页，是假登录框的高危信号
                return True, detected_brand
            # 检查 action 是否指向官方域名
            official_domains = {
                "google": ["accounts.google.com", "signin.google.com", "google.com"],
                "microsoft": ["login.microsoftonline.com", "login.live.com", "account.microsoft.com"],
                "adobe": ["account.adobe.com", "secure.adobe.com"],
                "apple": ["appleid.apple.com", "reportaproblem.apple.com"],
                "amazon": ["amazon.com", "aws.amazon.com"],
                "paypal": ["paypal.com"],
            }
            brand_domains = official_domains.get(detected_brand, [])
            if brand_domains:
                is_official = any(d in action.lower() for d in brand_domains)
                if not is_official:
                    return True, detected_brand

        # 有密码框但 action 都是官方 → 不判定为假登录（可能是正常的登录页）
        return False, ""

    def _detect_js_exfil(self, soup: BeautifulSoup, html_content: str) -> tuple[list[str], list[str]]:
        """
        检测 JS 数据外传和隐藏 URL。
        返回 (exfil_domains, hidden_urls)
        """
        import re as _re
        from urllib.parse import urlparse as _urlparse

        exfil_domains = []
        hidden_urls = []
        seen_domains = set()
        seen_hidden = set()

        # ── ① fetch / XMLHttpRequest / axios / $.ajax 数据外传 ──
        exfil_patterns = [
            _re.compile(r'fetch\s*\(\s*["\']([^"\']+)["\']', _re.IGNORECASE),
            _re.compile(r'new\s+XMLHttpRequest\s*\..*?open\s*\(\s*["\'][^"\']+["\']\s*,\s*["\']([^"\']+)["\']', _re.IGNORECASE | _re.DOTALL),
            _re.compile(r'\.post\s*\(\s*["\']([^"\']+)["\']', _re.IGNORECASE),
            _re.compile(r'axios\s*\.post\s*\(\s*["\']([^"\']+)["\']', _re.IGNORECASE),
            _re.compile(r'axios\s*\.get\s*\(\s*["\']([^"\']+)["\']', _re.IGNORECASE),
            _re.compile(r'\$.*ajax\s*\(\s*\{[^}]*url\s*:\s*["\']([^"\']+)["\']', _re.IGNORECASE | _re.DOTALL),
        ]

        for pat in exfil_patterns:
            for m in pat.finditer(html_content):
                url = m.group(1).strip()
                if url.startswith("http"):
                    try:
                        domain = _urlparse(url).netloc
                        if domain and domain not in seen_domains:
                            seen_domains.add(domain)
                            exfil_domains.append(domain)
                    except Exception:
                        pass

        # ── ② form action 外传（非官方域名已在假登录框中覆盖，此处补漏）────
        for form in soup.find_all("form"):
            action = form.get("action", "")
            if action and action.startswith("http"):
                try:
                    domain = _urlparse(action).netloc
                    if domain and domain not in seen_domains:
                        seen_domains.add(domain)
                        exfil_domains.append(domain)
                except Exception:
                    pass

        # ── ③ base64 编码隐藏 URL ──
        # 匹配 atob(...) 解码、base64 字符串
        b64_url_pattern = _re.compile(
            r'(?:atob\s*\(\s*["\']([^"\']+)["\']\s*\)|'
            r'(?:window|document|top)\.location\s*=\s*atob\(|'
            r'(?:href|src|action)\s*=\s*["\']data:[^"\']*;base64,([^"\'<>\s]+)',
            _re.IGNORECASE
        )
        for m in b64_url_pattern.finditer(html_content):
            b64_str = (m.group(1) or m.group(2) or "").strip()
            if not b64_str:
                continue
            # 尝试解码 base64
            try:
                import base64 as _b64
                decoded = _b64.b64decode(b64_str + "==").decode("utf-8", errors="ignore")
                if decoded.startswith("http"):
                    if decoded not in seen_hidden:
                        seen_hidden.add(decoded)
                        hidden_urls.append(decoded)
            except Exception:
                pass

        # 额外的 base64 解码模式：直接解 aHR0c... 风格字符串
        raw_b64_pattern = _re.compile(r'["\']([A-Za-z0-9+/]{20,}={0,2})["\']')
        for m in raw_b64_pattern.finditer(html_content):
            candidate = m.group(1)
            if candidate in seen_hidden:
                continue
            try:
                import base64 as _b64
                decoded = _b64.b64decode(candidate + "==").decode("utf-8", errors="ignore")
                if decoded.startswith("http") and len(decoded) < 500:
                    seen_hidden.add(candidate)
                    hidden_urls.append(decoded)
            except Exception:
                pass

        return exfil_domains[:10], hidden_urls[:10]

    def _detect_anti_analysis(self, html_lower: str) -> bool:
        """检测反分析代码：禁用右键、F12、开发者工具检测。"""
        anti_patterns = [
            "oncontextmenu",           # 禁用右键菜单
            "event.keycode",           # 禁用键盘
            "event.returnvalue=false", # 阻止默认行为
            "document.onkeydown",      # 键盘监控
            "nokey",                   # 防 F12
            "devtools",                # 开发者工具检测
            "f12",                     # F12 键禁用
            "ctrl+shift+i",            # 禁用开发者工具
            "ctrl+shift+j",
            "ctrl+shift+c",
            "window.onresize",         # 窗口大小变化检测（devtools 打开会触发）
            "document.body.clientwidth", # 同上
            "blockdevelopertools",
        ]
        return any(p in html_lower for p in anti_patterns)

    def _detect_anti_bot(self, html_lower: str) -> bool:
        """检测反机器人检测代码：WebDriver、Puppeteer、Selenium、PhantomJS。"""
        bot_patterns = [
            "navigator.webdriver",
            "webdriver",
            "__puppeteer__",
            "__selenium__",
            "phantomjs",
            "callphantom",
            "callfromphantom",
            "selenium",
            "puppeteer",
            "playwright",
            "automation",
        ]
        return any(p in html_lower for p in bot_patterns)

    def _extract_attachments(self, msg) -> tuple[list[AttachmentInfo], dict[str, bytes]]:
        """提取附件信息和二进制数据"""
        attachments = []
        attachment_data_map = {}

        try:
            if not msg.is_multipart():
                return attachments, attachment_data_map

            for part in msg.walk():
                disposition = str(part.get("Content-Disposition", ""))
                if "attachment" not in disposition:
                    continue

                # 文件名
                filename = part.get_filename()
                if filename:
                    filename = self._decode_header_value(filename)
                else:
                    filename = "unknown_attachment"

                # 二进制数据
                payload = part.get_payload(decode=True)
                if payload is None:
                    payload = b""

                # 扩展名
                ext = ""
                if "." in filename:
                    ext = "." + filename.rsplit(".", 1)[-1].lower()

                # MIME 类型
                mime_type = part.get_content_type()

                # SHA256
                sha256 = hashlib.sha256(payload).hexdigest() if payload else ""

                att_info = AttachmentInfo(
                    filename=filename,
                    extension=ext,
                    mime_type=mime_type,
                    size=len(payload),
                    sha256=sha256,
                    data_length=len(payload),
                )

                attachments.append(att_info)
                attachment_data_map[filename] = payload

        except Exception as e:
            logger.error(f"提取附件失败: {e}")

        return attachments, attachment_data_map
