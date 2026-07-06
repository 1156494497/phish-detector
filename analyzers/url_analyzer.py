"""
URL 分析器
分析邮件中的链接：域名年龄、仿冒检测、短链追踪、可疑特征等
"""
import re
import time
import logging
from urllib.parse import urlparse

import requests
import whois

from models import URLDetail, URLAnalysisResult
from config import (
    SHORT_URL_SERVICES,
    FREE_HOSTING_PLATFORMS,
    SUSPICIOUS_URL_KEYWORDS,
    COMMON_BRANDS,
    WHOIS_CACHE_TTL,
)

logger = logging.getLogger(__name__)

# IP 地址正则
IP_PATTERN = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')

# URL 提取正则（用于 display_text 中检测 URL）
URL_PATTERN = re.compile(
    r'https?://[^\s<>"\'\)\]\\]+',
    re.IGNORECASE
)

# WHOIS 缓存
_whois_cache: dict[str, tuple[float, dict]] = {}


class URLAnalyzer:
    """分析邮件中的 URL 链接"""

    async def analyze(self, urls: list[str], url_display_map: dict[str, str] = None, vt_checker=None) -> URLAnalysisResult:
        """
        分析 URL 列表

        Args:
            urls: 从邮件中提取的 URL 列表
            url_display_map: {url: display_text} 链接显示文本映射
            vt_checker: 可选的 VirusTotal 查询器

        Returns:
            URLAnalysisResult
        """
        if not urls:
            return URLAnalysisResult(
                urls_analyzed=[],
                max_score=0,
                findings=["邮件中未发现任何链接"]
            )

        if url_display_map is None:
            url_display_map = {}

        results = []
        all_findings = []

        for url in urls:
            display_text = url_display_map.get(url, "")
            detail = self._analyze_single_url(url, display_text)
            # VirusTotal URL 信誉查询（异步）
            if vt_checker and vt_checker.enabled:
                vt_result = await vt_checker.check_url(url)
                if vt_result.get("checked"):
                    detail.vt_checked = True
                    detail.vt_malicious_count = vt_result.get("malicious_count", 0)
                    detail.vt_total_engines = vt_result.get("total_engines", 0)
                    detail.vt_reputation = vt_result.get("reputation", 0)
                    # VT 评分: 报毒引擎数占比
                    if detail.vt_total_engines > 0 and detail.vt_malicious_count > 0:
                        vt_score = min(int(detail.vt_malicious_count / detail.vt_total_engines * 100), 95)
                        detail.score = min(max(detail.score, vt_score), 100)
                    elif detail.vt_reputation < -10:
                        detail.score = min(max(detail.score, 60), 100)
                    detail.findings.extend(vt_result.get("findings", []))
            results.append(detail)
            all_findings.extend(detail.findings)

        max_score = max((r.score for r in results), default=0)

        return URLAnalysisResult(
            urls_analyzed=results,
            max_score=max_score,
            findings=all_findings,
        )

    def _analyze_single_url(self, url: str, display_text: str = "") -> URLDetail:
        """分析单个 URL"""
        parsed = urlparse(url)
        domain = parsed.netloc.lower().split(":")[0]  # 去掉端口
        findings = []
        score = 0

        detail = URLDetail(
            url=url,
            domain=domain,
            is_https=(parsed.scheme == "https"),
            display_text=display_text,
        )

        # 1. IP 地址 URL 检测
        if IP_PATTERN.match(domain):
            score += 90
            detail.is_ip_url = True
            findings.append(f"URL 使用 IP 地址代替域名: {domain}")

        # 2. @ 符号检测（URL 中包含 @ 可能是伪装）
        if "@" in parsed.netloc:
            score += 70
            findings.append(f"URL 中包含 @ 符号，可能用于伪装域名")

        # 3. HTTPS 检测
        if not detail.is_https:
            score += 20
            findings.append("URL 未使用 HTTPS 加密连接")

        # 4. 域名年龄检测
        domain_age = self._get_domain_age(domain)
        if domain_age is not None:
            detail.domain_age_days = domain_age
            if domain_age < 30:
                score += 80
                findings.append(f"域名注册仅 {domain_age} 天（< 30天），极高风险")
            elif domain_age < 90:
                score += 50
                findings.append(f"域名注册 {domain_age} 天（< 90天），中等风险")
            elif domain_age < 180:
                score += 20
                findings.append(f"域名注册 {domain_age} 天（< 180天），需关注")

        # 5. 品牌仿冒检测（支持三类）
        brand_match, kind = self._check_typosquatting(domain)
        if brand_match:
            score += 85
            detail.typosquat_brand = brand_match
            detail.typosquat_kind = kind
            kind_desc = {
                "name_match": "主名混淆",
                "prefix": "含品牌前缀",
                "suffix": "含品牌后缀",
                "subdomain": "品牌放在子域名",
            }.get(kind, kind)
            findings.append(f"疑似仿冒品牌域名: {domain} → 可能冒充 {brand_match}（{kind_desc}）")

        # 6. 短链接检测
        if domain in SHORT_URL_SERVICES or any(domain.endswith(f".{s}") for s in SHORT_URL_SERVICES):
            detail.is_short_url = True
            score += 30
            findings.append(f"URL 使用短链接服务: {domain}")
            # 尝试跟踪重定向
            redirect_chain, final_domain = self._follow_redirects(url)
            detail.redirect_chain = redirect_chain
            detail.final_domain = final_domain
            if final_domain and final_domain != domain:
                score += 40
                findings.append(f"短链接重定向到不同域名: {final_domain}")

        # 7. 免费托管平台检测
        if self._is_free_hosting(domain):
            score += 30
            detail.is_free_hosting = True
            findings.append(f"URL 托管在免费平台: {domain}")

        # 8. 可疑关键词检测
        url_lower = url.lower()
        found_keywords = []
        for kw in SUSPICIOUS_URL_KEYWORDS:
            if kw in url_lower:
                found_keywords.append(kw)
        if found_keywords:
            score += min(len(found_keywords) * 15, 50)  # 每个关键词15分，上限50
            detail.suspicious_keywords = found_keywords
            findings.append(f"URL 中包含可疑关键词: {', '.join(found_keywords)}")

        # 9. 超长子域名检测
        subdomain_parts = domain.split(".")
        if len(subdomain_parts) > 4:
            score += 30
            findings.append(f"URL 包含过多子域名层级: {domain}")

        # 10. 域名过长检测
        if len(domain) > 50:
            score += 20
            findings.append(f"域名异常过长 ({len(domain)} 字符)")

        # 11. 显示文本 vs href 域名不一致检测
        if display_text:
            # 检查显示文本中是否包含 URL
            display_urls = URL_PATTERN.findall(display_text)
            if display_urls:
                try:
                    display_domain = urlparse(display_urls[0]).netloc.lower().split(":")[0]
                    if display_domain and display_domain != domain:
                        score += 85
                        detail.href_mismatch = True
                        findings.append(
                            f"链接显示文本指向 {display_domain} 但实际跳转到 {domain}"
                        )
                except Exception:
                    pass
            else:
                # 显示文本不是 URL，检查是否包含品牌名但 href 域名不匹配
                display_lower = display_text.lower()
                for brand, official_domains in COMMON_BRANDS.items():
                    for official in official_domains:
                        official_name = official.split(".")[0]
                        if (len(official_name) > 3 and official_name in display_lower
                                and official_name not in domain and brand not in domain):
                            score += 75
                            detail.href_mismatch = True
                            findings.append(
                                f"链接显示文本包含 '{official_name}' 但实际域名 {domain} 不匹配"
                            )
                            break
                    if detail.href_mismatch:
                        break

        detail.score = min(score, 100)
        detail.findings = findings
        return detail

    def _get_domain_age(self, domain: str) -> int | None:
        """查询域名年龄（天），带缓存"""
        # 检查缓存
        if domain in _whois_cache:
            cached_time, cached_data = _whois_cache[domain]
            if time.time() - cached_time < WHOIS_CACHE_TTL:
                return cached_data.get("age_days")

        try:
            w = whois.whois(domain)
            creation_date = w.creation_date
            if creation_date:
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                age_days = (time.time() - creation_date.timestamp()) / 86400
                age_days = int(age_days)
                _whois_cache[domain] = (time.time(), {"age_days": age_days})
                return age_days
        except Exception as e:
            logger.warning(f"WHOIS 查询失败 [{domain}]: {e}")

        _whois_cache[domain] = (time.time(), {"age_days": None})
        return None

    def _check_typosquatting(self, domain: str) -> tuple[str, str]:
        """
        检测域名是否仿冒常见品牌。

        Returns:
            (被仿冒的品牌名, 仿冒类型) 或 ("", "")。
            仿冒类型:
              - "name_match": 主域名与品牌主名编辑距离近（typosquatting）
              - "prefix": 域名主名前缀含品牌名（如 microsoft-login.com）
              - "suffix": 域名主名后缀含品牌名（如 login-microsoft.com）
              - "subdomain": 品牌名被放在子域名中（如 microsoft.attacker.com）
              - "path": URL 路径中出现品牌名但域名非官方
        """
        if not domain:
            return "", ""

        # 提取主域名（去掉 TLD）
        parts = domain.lower().split(".")
        if len(parts) < 2:
            return "", ""
        domain_name = parts[0]  # e.g. "microsoft-security"

        for brand, info in COMMON_BRANDS.items():
            main_names = info.get("main_names", [])
            official_domains = info.get("official_domains", [])
            official_main = [d.split(".")[0] for d in official_domains if "." in d]

            for brand_name in main_names:
                brand_lower = brand_name.lower()

                # ── 1) 主名混淆（name_match）：domain_name 与 brand_name 编辑距离 ≤ 2 ──
                if len(brand_lower) > 3:
                    dist = self._levenshtein_distance(domain_name, brand_lower)
                    if 0 < dist <= 2:
                        return brand, "name_match"

                # ── 2) 品牌前缀/后缀：microsoft-login / login-microsoft ──
                if brand_lower in domain_name and domain_name != brand_lower:
                    # 品牌作为前缀: microsoft-login
                    if domain_name.startswith(brand_lower + "-") or domain_name.startswith(brand_lower + "."):
                        return brand, "prefix"
                    # 品牌作为后缀: login-microsoft
                    if domain_name.endswith("-" + brand_lower) or domain_name.endswith("." + brand_lower):
                        return brand, "suffix"
                    # 品牌在中间: attacker-microsoft-site（以 - 分隔）
                    if "-" in domain_name:
                        parts2 = domain_name.split("-")
                        if brand_lower in parts2:
                            return brand, "prefix"  # 含品牌的分段，视为前缀类型

                # ── 3) 品牌放子域名: microsoft.attacker.com ──
                if len(parts) >= 3:
                    subdomain = parts[0]  # 第一个子域名
                    # 品牌名出现在子域名里
                    if brand_lower in subdomain and subdomain != brand_lower:
                        return brand, "subdomain"

                # ── 4) 官方主名在域名里（如 microsoft-security 包含 microsoft）────
                for official_main_name in official_main:
                    if len(official_main_name) > 3:
                        if official_main_name in domain_name and domain_name != official_main_name:
                            return brand, "prefix"

        return "", ""

    @staticmethod
    def _levenshtein_distance(s1: str, s2: str) -> int:
        """计算两个字符串的编辑距离"""
        if len(s1) < len(s2):
            return URLAnalyzer._levenshtein_distance(s2, s1)
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

    def _follow_redirects(self, url: str, max_redirects: int = 5) -> tuple[list[str], str]:
        """跟踪 URL 重定向链"""
        chain = []
        try:
            resp = requests.get(url, allow_redirects=False, timeout=5, verify=False)
            for _ in range(max_redirects):
                if resp.status_code not in (301, 302, 303, 307, 308):
                    break
                location = resp.headers.get("Location", "")
                if not location:
                    break
                chain.append(location)
                if location.startswith("http"):
                    resp = requests.get(location, allow_redirects=False, timeout=5, verify=False)
                else:
                    break
        except Exception as e:
            logger.warning(f"重定向跟踪失败 [{url}]: {e}")

        final_domain = ""
        if chain:
            try:
                final_domain = urlparse(chain[-1]).netloc.lower()
            except Exception:
                pass

        return chain, final_domain

    def _is_free_hosting(self, domain: str) -> bool:
        """检测是否为免费托管平台"""
        for platform in FREE_HOSTING_PLATFORMS:
            if domain == platform or domain.endswith(f".{platform}"):
                return True
        return False
