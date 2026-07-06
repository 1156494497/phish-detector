"""
MSG 文件解析器
从 .msg 文件中提取邮件元数据、正文、URL、附件
"""
import re
import hashlib
import json
import logging
from io import BytesIO
from urllib.parse import urlparse, unquote

import extract_msg
from extract_msg.enums import ErrorBehavior
from bs4 import BeautifulSoup

from models import ParsedEmail, EmailMetadata, AttachmentInfo, HtmlAnalysisResult

logger = logging.getLogger(__name__)

LOG_PATH = "debug-f1fce3.log"
SESSION_ID = "f1fce3"


def _debug_log(*, run_id: str, hypothesis_id: str, location: str, message: str, data: dict) -> None:
    try:
        payload = {
            "sessionId": SESSION_ID,
            "id": f"log_{int(__import__('time').time()*1000)}_{hypothesis_id}",
            "timestamp": int(__import__('time').time() * 1000),
            "location": location,
            "message": message,
            "data": data,
            "runId": run_id,
            "hypothesisId": hypothesis_id,
        }
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(payload, ensure_ascii=False) + "\n")
    except Exception:
        pass


# URL 提取正则
URL_PATTERN = re.compile(
    r'https?://[^\s<>"\'\)\]\\]+',
    re.IGNORECASE
)

# HTML href 提取
HREF_PATTERN = re.compile(
    r'href=["\']([^"\']+)["\']',
    re.IGNORECASE
)


class MsgParser:
    """解析 .msg 文件，提取结构化邮件数据"""

    def parse(self, data: bytes) -> tuple[ParsedEmail, dict[str, bytes]]:
        """
        解析 .msg 文件二进制数据

        Args:
            data: .msg 文件二进制内容

        Returns:
            (parsed_email, attachment_data_map)
            attachment_data_map: {filename: binary_data} 附件数据映射
        """
        _debug_log(run_id="repro", hypothesis_id="H0", location="msg_parser.py:parse:enter", message="parse_enter", data={"bytes": len(data)})
        msg = extract_msg.Message(
            BytesIO(data),
            deencapsulationFunc=lambda rtf, dtype: None,
            errorBehavior=ErrorBehavior.RTFDE,
        )

        try:
            try:
                metadata = self._extract_metadata(msg)
                body_text = self._extract_body_text(msg)
                body_html = self._extract_body_html(msg)
                urls, url_display_map = self._extract_urls(body_text, body_html)
                attachments, attachment_data = self._extract_attachments(msg)
            except re.error as e:
                _debug_log(run_id="repro", hypothesis_id="H_outer", location="msg_parser.py:parse:except_re", message="parse_re_fallback", data={"error": str(e)})
                logger.warning(f"MSG 解析触发正则异常，降级为部分结果继续分析: {e}")
                metadata = metadata if 'metadata' in locals() else self._build_empty_metadata(msg)
                body_text = body_text if 'body_text' in locals() else ""
                body_html = ""
                urls, url_display_map = [], {}
                attachments, attachment_data = [], {}

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

            _debug_log(run_id="repro", hypothesis_id="H_return", location="msg_parser.py:parse:before_return", message="parse_before_return", data={"urls": len(urls), "attachments": len(attachments)})
            return parsed, attachment_data

        finally:
            _debug_log(run_id="repro", hypothesis_id="H_close", location="msg_parser.py:parse:finally", message="parse_finally", data={})
            msg.close()
            _debug_log(run_id="repro", hypothesis_id="H_close", location="msg_parser.py:parse:finally_after", message="parse_finally_after", data={})

    def _build_empty_metadata(self, msg) -> EmailMetadata:
        subject = msg.subject if hasattr(msg, "subject") and msg.subject is not None else ""
        return EmailMetadata(
            sender_name="",
            sender_email="",
            sender_domain="",
            to=[],
            cc=[],
            subject=subject or "",
            date="",
            message_id="",
            headers="",
        )

    def _extract_metadata(self, msg) -> EmailMetadata:
        """提取邮件元数据"""
        _debug_log(run_id="repro", hypothesis_id="H_meta", location="msg_parser.py:_extract_metadata:enter", message="metadata_enter", data={})
        sender_email = ""
        sender_name = ""
        try:
            sender_email = msg.sender or ""
        except Exception as e:
            _debug_log(run_id="repro", hypothesis_id="H4", location="msg_parser.py:_extract_metadata:sender", message="property_error", data={"property": "sender", "error": f"{type(e).__name__}: {e}"})

        # 解析发件人（格式可能是 "Name <email>" 或纯 email）
        if "<" in sender_email and ">" in sender_email:
            try:
                match = re.match(r'^(.+?)\s*<(.+?)>', sender_email)
                if match:
                    sender_name = match.group(1).strip().strip('"')
                    sender_email = match.group(2).strip()
            except Exception as e:
                _debug_log(run_id="repro", hypothesis_id="H_meta", location="msg_parser.py:_extract_metadata:sender_re", message="re_error", data={"error": f"{type(e).__name__}: {e}"})

        # 提取发件人域名
        sender_domain = ""
        if "@" in sender_email:
            sender_domain = sender_email.split("@")[-1].lower()

        # 收件人列表
        to_list = []
        try:
            if msg.to:
                to_list = [addr.strip() for addr in str(msg.to).split(";") if addr.strip()]
        except Exception as e:
            _debug_log(run_id="repro", hypothesis_id="H4", location="msg_parser.py:_extract_metadata:to", message="property_error", data={"property": "to", "error": f"{type(e).__name__}: {e}"})

        cc_list = []
        try:
            if msg.cc:
                cc_list = [addr.strip() for addr in str(msg.cc).split(";") if addr.strip()]
        except Exception as e:
            _debug_log(run_id="repro", hypothesis_id="H4", location="msg_parser.py:_extract_metadata:cc", message="property_error", data={"property": "cc", "error": f"{type(e).__name__}: {e}"})

        # 邮件头
        headers = ""
        try:
            try:
                headers = msg.header.text if msg.header else ""
            except re.error as e:
                _debug_log(run_id="repro", hypothesis_id="H1", location="msg_parser.py:_extract_metadata:header_text", message="re_error", data={"error": str(e)})
                logger.warning(f"邮件头解析触发 re.error，丢弃: {e}")
                headers = ""
            except Exception as e:
                _debug_log(run_id="repro", hypothesis_id="H1", location="msg_parser.py:_extract_metadata:header_text", message="property_error", data={"error": f"{type(e).__name__}: {e}"})
                headers = ""
        except Exception:
            headers = ""

        subject = ""
        date = ""
        message_id = ""
        try:
            subject = msg.subject or ""
        except Exception as e:
            _debug_log(run_id="repro", hypothesis_id="H4", location="msg_parser.py:_extract_metadata:subject", message="property_error", data={"property": "subject", "error": f"{type(e).__name__}: {e}"})
        try:
            date = str(msg.date) if msg.date else ""
        except Exception as e:
            _debug_log(run_id="repro", hypothesis_id="H4", location="msg_parser.py:_extract_metadata:date", message="property_error", data={"property": "date", "error": f"{type(e).__name__}: {e}"})
        try:
            message_id = msg.messageId or ""
        except Exception as e:
            _debug_log(run_id="repro", hypothesis_id="H4", location="msg_parser.py:_extract_metadata:message_id", message="property_error", data={"property": "messageId", "error": f"{type(e).__name__}: {e}"})

        return EmailMetadata(
            sender_name=sender_name,
            sender_email=sender_email,
            sender_domain=sender_domain,
            to=to_list,
            cc=cc_list,
            subject=subject,
            date=date,
            message_id=message_id,
            headers=headers,
        )

    def _extract_body_text(self, msg) -> str:
        """提取纯文本正文"""
        _debug_log(run_id="repro", hypothesis_id="H2", location="msg_parser.py:_extract_body_text:enter", message="body_text_enter", data={})
        try:
            try:
                body = msg.body
                _debug_log(run_id="repro", hypothesis_id="H2", location="msg_parser.py:_extract_body_text:after", message="body_text_after", data={"len": len(body) if isinstance(body, str) else -1})
                return body if body else ""
            except re.error as e:
                _debug_log(run_id="repro", hypothesis_id="H2", location="msg_parser.py:_extract_body_text:re", message="re_error", data={"error": str(e)})
                logger.warning(f"纯文本正文解析触发 re.error，丢弃: {e}")
                return ""
        except Exception as e:
            _debug_log(run_id="repro", hypothesis_id="H2", location="msg_parser.py:_extract_body_text:exception", message="exception", data={"error": f"{type(e).__name__}: {e}"})
            logger.warning(f"提取纯文本正文失败: {e}")
            return ""

    def _extract_body_html(self, msg) -> str:
        """提取 HTML 正文"""
        _debug_log(run_id="repro", hypothesis_id="H3", location="msg_parser.py:_extract_body_html:enter", message="body_html_enter", data={})
        try:
            try:
                html = msg.htmlBody
                _debug_log(run_id="repro", hypothesis_id="H3", location="msg_parser.py:_extract_body_html:after", message="body_html_after", data={"len": len(html) if isinstance(html, (str, bytes)) else -1, "type": type(html).__name__})
            except re.error as e:
                _debug_log(run_id="repro", hypothesis_id="H3", location="msg_parser.py:_extract_body_html:re", message="re_error", data={"error": str(e)})
                logger.warning(f"htmlBody 解析触发 re.error，丢弃: {e}")
                return ""
            if html:
                if isinstance(html, bytes):
                    html = html.decode("utf-8", errors="ignore")
                return html
        except Exception as e:
            _debug_log(run_id="repro", hypothesis_id="H3", location="msg_parser.py:_extract_body_html:exception", message="exception", data={"error": f"{type(e).__name__}: {e}"})
            logger.warning(f"提取HTML正文失败: {e}")
        return ""

    def _extract_urls(self, body_text: str, body_html: str) -> tuple[list[str], dict[str, str]]:
        """从正文中提取并去重 URL，同时提取显示文本"""
        urls = set()
        url_display_map = {}  # {url: display_text}

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
                # 回退到正则
                for match in HREF_PATTERN.findall(body_html):
                    url = self._normalize_url(match)
                    if url:
                        urls.add(url)

        # 从纯文本和 HTML 文本中补充提取
        for text in [body_text, body_html]:
            if text:
                for match in URL_PATTERN.findall(text):
                    url = self._normalize_url(match)
                    if url:
                        urls.add(url)

        return sorted(urls), url_display_map

    def _normalize_url(self, url: str) -> str:
        """规范化 URL：解码、去尾随标点"""
        url = unquote(url.strip())
        # 去除尾部可能的标点符号
        url = url.rstrip(".,;:!?)]}>")
        # 过滤无效 URL
        if not url or len(url) < 10:
            return ""
        parsed = urlparse(url)
        if not parsed.scheme or not parsed.netloc:
            return ""
        return url

    def _extract_html_signals(self, body_html: str) -> HtmlAnalysisResult:
        """提取 HTML 结构信号：表单、追踪像素、隐藏文本"""
        _debug_log(run_id="repro", hypothesis_id="H_html", location="msg_parser.py:_extract_html_signals:enter", message="html_signals_enter", data={"len": len(body_html) if body_html else 0})
        if not body_html:
            _debug_log(run_id="repro", hypothesis_id="H_html", location="msg_parser.py:_extract_html_signals:empty", message="html_signals_empty", data={})
            return HtmlAnalysisResult()

        try:
            soup = BeautifulSoup(body_html, "html.parser")
        except Exception as e:
            _debug_log(run_id="repro", hypothesis_id="H_html", location="msg_parser.py:_extract_html_signals:bs4", message="html_signals_bs4_error", data={"error": f"{type(e).__name__}: {e}"})
            logger.warning(f"HTML 结构分析失败: {e}")
            return HtmlAnalysisResult()

        findings = []
        html_lower = body_html.lower()

        # 1. 基础：表单检测
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

        # 2. 追踪像素检测
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

        # 3. 隐藏文本检测
        hidden_count = 0
        for tag in soup.find_all(style=True):
            s = tag["style"].lower().replace(" ", "")
            if "display:none" in s or "visibility:hidden" in s or "opacity:0" in s:
                hidden_count += 1
        if hidden_count:
            findings.append(f"检测到 {len(hidden_count)} 个隐藏元素（display:none/visibility:hidden/opacity:0）")

        # 4. 假登录框检测
        has_fake_login, fake_brand = self._detect_fake_login(soup, forms, html_lower)
        if has_fake_login:
            findings.append(f"检测到假登录框：疑似仿冒 {fake_brand} 登录界面")

        # 5. 深度 JS 分析
        exfil_domains, hidden_urls = self._detect_js_exfil(soup, body_html)
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

    def _detect_fake_login(self, soup, forms, html_lower):
        import re
        from urllib.parse import urlparse
        password_inputs = soup.find_all("input", {"type": lambda t: t and t.lower() in ("password", "email")})
        if not password_inputs:
            return False, ""
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
        official_domains = {
            "google": ["accounts.google.com", "signin.google.com", "google.com"],
            "microsoft": ["login.microsoftonline.com", "login.live.com", "account.microsoft.com"],
            "adobe": ["account.adobe.com", "secure.adobe.com"],
            "apple": ["appleid.apple.com", "reportaproblem.apple.com"],
            "amazon": ["amazon.com", "aws.amazon.com"],
            "paypal": ["paypal.com"],
        }
        for form in forms:
            action = form.get("action", "").strip()
            if not action:
                return True, detected_brand
            brand_domains = official_domains.get(detected_brand, [])
            if brand_domains:
                is_official = any(d in action.lower() for d in brand_domains)
                if not is_official:
                    return True, detected_brand
        return False, ""

    def _detect_js_exfil(self, soup, html_content):
        _debug_log(run_id="repro", hypothesis_id="H_js", location="msg_parser.py:_detect_js_exfil:enter", message="js_exfil_enter", data={"len": len(html_content) if html_content else 0})
        import re
        from urllib.parse import urlparse
        import base64
        exfil_domains = []
        hidden_urls = []
        seen_domains = set()
        seen_hidden = set()
        try:
            exfil_patterns = [
                re.compile(r'fetch\s*\(\s*["\']([^"\']+)["\']', re.IGNORECASE),
                re.compile(r'new\s+XMLHttpRequest\s*\..*?open\s*\(\s*["\'][^"\']+["\']\s*,\s*["\']([^"\']+)["\']', re.IGNORECASE | re.DOTALL),
                re.compile(r'\.post\s*\(\s*["\']([^"\']+)["\']', re.IGNORECASE),
                re.compile(r'axios\s*\.post\s*\(\s*["\']([^"\']+)["\']', re.IGNORECASE),
                re.compile(r'axios\s*\.get\s*\(\s*["\']([^"\']+)["\']', re.IGNORECASE),
                re.compile(r'\$.*ajax\s*\(\s*\{[^}]*url\s*:\s*["\']([^"\']+)["\']', re.IGNORECASE | re.DOTALL),
            ]
            for pat in exfil_patterns:
                for m in pat.finditer(html_content):
                    url = m.group(1).strip()
                    if url.startswith("http"):
                        try:
                            domain = urlparse(url).netloc
                            if domain and domain not in seen_domains:
                                seen_domains.add(domain)
                                exfil_domains.append(domain)
                        except Exception:
                            pass
            for form in soup.find_all("form"):
                action = form.get("action", "")
                if action and action.startswith("http"):
                    try:
                        domain = urlparse(action).netloc
                        if domain and domain not in seen_domains:
                            seen_domains.add(domain)
                            exfil_domains.append(domain)
                    except Exception:
                        pass
            b64_url_pattern = re.compile(
                r'(?:atob\s*\(\s*["\']([^"\']+)["\']\s*\)|'
                r'(?:window|document|top)\.location\s*=\s*atob\(|)'
                r'|(?:href|src|action)\s*=\s*["\']data:[^"\']*;base64,([^"\'<>\s]+)',
                re.IGNORECASE
            )
            for m in b64_url_pattern.finditer(html_content):
                b64_str = (m.group(1) or m.group(2) or "").strip()
                if not b64_str:
                    continue
                try:
                    decoded = base64.b64decode(b64_str + "==").decode("utf-8", errors="ignore")
                    if decoded.startswith("http"):
                        if decoded not in seen_hidden:
                            seen_hidden.add(decoded)
                            hidden_urls.append(decoded)
                except Exception:
                    pass
            raw_b64_pattern = re.compile(r'["\']([A-Za-z0-9+/]{20,}={0,2})["\']')
            for m in raw_b64_pattern.finditer(html_content):
                candidate = m.group(1)
                if candidate in seen_hidden:
                    continue
                try:
                    decoded = base64.b64decode(candidate + "==").decode("utf-8", errors="ignore")
                    if decoded.startswith("http") and len(decoded) < 500:
                        seen_hidden.add(candidate)
                        hidden_urls.append(decoded)
                except Exception:
                    pass
        except re.error:
            logger.warning("JS exfil 正则编译失败，跳过")
            return [], []
        return exfil_domains[:10], hidden_urls[:10]

    def _detect_anti_analysis(self, html_lower):
        anti_patterns = [
            "oncontextmenu", "event.keycode", "event.returnvalue=false",
            "document.onkeydown", "nokey", "devtools", "f12",
            "ctrl+shift+i", "ctrl+shift+j", "ctrl+shift+c",
            "window.onresize", "document.body.clientwidth",
            "blockdevelopertools",
        ]
        return any(p in html_lower for p in anti_patterns)

    def _detect_anti_bot(self, html_lower):
        bot_patterns = [
            "navigator.webdriver", "webdriver", "__puppeteer__",
            "__selenium__", "phantomjs", "callphantom", "callfromphantom",
            "selenium", "puppeteer", "playwright", "automation",
        ]
        return any(p in html_lower for p in bot_patterns)

    def _extract_attachments(self, msg) -> tuple[list[AttachmentInfo], dict[str, bytes]]:
        """提取附件信息和二进制数据"""
        _debug_log(run_id="repro", hypothesis_id="H5", location="msg_parser.py:_extract_attachments:enter", message="attachments_enter", data={})
        attachments = []
        attachment_data_map = {}

        try:
            for att in msg.attachments:
                # 跳过嵌入的 msg 附件（嵌套邮件）
                if isinstance(att, extract_msg.attachments.EmbeddedMsgAttachment):
                    logger.info("发现嵌套 msg 附件，跳过")
                    continue

                filename = att.longFilename or att.shortFilename or "unknown"
                data = att.data or b""

                # 计算文件扩展名
                ext = ""
                if "." in filename:
                    ext = "." + filename.rsplit(".", 1)[-1].lower()

                # 计算 SHA256
                sha256 = hashlib.sha256(data).hexdigest() if data else ""

                # MIME 类型
                mime_type = att.mimetype or ""

                att_info = AttachmentInfo(
                    filename=filename,
                    extension=ext,
                    mime_type=mime_type,
                    size=len(data),
                    sha256=sha256,
                    data_length=len(data),
                )

                attachments.append(att_info)
                attachment_data_map[filename] = data

        except Exception as e:
            _debug_log(run_id="repro", hypothesis_id="H5", location="msg_parser.py:_extract_attachments:exception", message="exception", data={"error": f"{type(e).__name__}: {e}"})
            logger.error(f"提取附件失败: {e}")

        return attachments, attachment_data_map
