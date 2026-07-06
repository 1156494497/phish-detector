"""
VirusTotal 查询模块（异步版）
查 URL 信誉和文件哈希信誉，使用 aiohttp 非阻塞请求
"""
import asyncio
import time
import logging
import hashlib
import base64
from urllib.parse import urlparse

import aiohttp

from config import VT_API_KEY, VT_BASE_URL, VT_TIMEOUT, VT_CACHE_TTL, VT_RATE_LIMIT_DELAY

logger = logging.getLogger(__name__)

# 查询缓存: {key: (timestamp, data)}
_cache: dict[str, tuple[float, dict]] = {}
_last_query_time: float = 0.0
_rate_lock = asyncio.Lock()


class VTChecker:
    """VirusTotal API 查询器（异步）"""

    def __init__(self):
        self.api_key = VT_API_KEY
        self.base_url = VT_BASE_URL
        self.enabled = bool(self.api_key)
        if not self.enabled:
            logger.warning("VirusTotal API Key 未配置，VT查询不可用")

    def _get_headers(self) -> dict:
        return {"x-apikey": self.api_key, "Accept": "application/json"}

    async def _rate_limit_wait(self):
        """禁用限速时直接跳过；有延迟时每两次查询间隔 VT_RATE_LIMIT_DELAY 秒（异步非阻塞）"""
        if VT_RATE_LIMIT_DELAY <= 0:
            return
        global _last_query_time
        async with _rate_lock:
            elapsed = time.time() - _last_query_time
            if elapsed < VT_RATE_LIMIT_DELAY:
                wait = VT_RATE_LIMIT_DELAY - elapsed
                logger.info(f"VT 限速等待 {wait:.1f}s...")
                await asyncio.sleep(wait)
            _last_query_time = time.time()

    def _get_cached(self, key: str) -> dict | None:
        """从缓存获取"""
        if key in _cache:
            ts, data = _cache[key]
            if time.time() - ts < VT_CACHE_TTL:
                return data
        return None

    def _set_cached(self, key: str, data: dict):
        """写入缓存"""
        _cache[key] = (time.time(), data)
        # 清理过期缓存
        now = time.time()
        expired = [k for k, (ts, _) in _cache.items() if now - ts > VT_CACHE_TTL]
        for k in expired:
            del _cache[k]

    async def check_url(self, url: str) -> dict:
        """
        异步查询 URL 的 VirusTotal 信誉

        Returns:
            {
                "checked": bool,
                "malicious_count": int,
                "total_engines": int,
                "reputation": int,
                "categories": list,
                "findings": list[str],
            }
        """
        if not self.enabled:
            return {"checked": False, "malicious_count": 0, "total_engines": 0, "reputation": 0, "findings": []}

        cache_key = f"url:{url}"
        cached = self._get_cached(cache_key)
        if cached:
            logger.info(f"VT URL 缓存命中: {url}")
            return cached

        # VT URL ID = base64url(url) 去掉等号
        url_id = base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")

        try:
            await self._rate_limit_wait()
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=VT_TIMEOUT)
            ) as session:
                async with session.get(
                    f"{self.base_url}/urls/{url_id}",
                    headers=self._get_headers(),
                ) as resp:
                    if resp.status == 404:
                        # URL 未被 VT 收录，尝试提交扫描
                        result = await self._submit_url_scan(url, session)
                        self._set_cached(cache_key, result)
                        return result

                    if resp.status != 200:
                        logger.warning(f"VT URL 查询失败 [{resp.status}]: {url}")
                        return {"checked": False, "malicious_count": 0, "total_engines": 0, "reputation": 0, "findings": [f"VT查询失败: HTTP {resp.status}"]}

                    data = await resp.json()

            attrs = data.get("data", {}).get("attributes", {})
            last_analysis = attrs.get("last_analysis_results", {})
            malicious_count = sum(1 for v in last_analysis.values() if v.get("category") == "malicious")
            total_engines = len(last_analysis)
            reputation = attrs.get("reputation", 0)
            categories = list(attrs.get("categories", {}).keys())

            findings = []
            if malicious_count > 0:
                findings.append(f"VirusTotal: {malicious_count}/{total_engines} 引擎判定为恶意")
            if reputation < 0:
                findings.append(f"VirusTotal 声誉分: {reputation} (负面)")
            if categories:
                findings.append(f"VT 分类: {', '.join(categories[:5])}")

            result = {
                "checked": True,
                "malicious_count": malicious_count,
                "total_engines": total_engines,
                "reputation": reputation,
                "categories": categories,
                "findings": findings,
            }

            self._set_cached(cache_key, result)
            logger.info(f"VT URL 查询完成: {url} -> {malicious_count}/{total_engines} malicious")
            return result

        except asyncio.TimeoutError:
            logger.warning(f"VT URL 查询超时: {url}")
            return {"checked": False, "malicious_count": 0, "total_engines": 0, "reputation": 0, "findings": ["VT查询超时"]}
        except Exception as e:
            logger.error(f"VT URL 查询异常: {e}")
            return {"checked": False, "malicious_count": 0, "total_engines": 0, "reputation": 0, "findings": [f"VT查询异常: {str(e)}"]}

    async def _submit_url_scan(self, url: str, session: aiohttp.ClientSession) -> dict:
        """提交 URL 到 VT 扫描"""
        try:
            await self._rate_limit_wait()
            async with session.post(
                f"{self.base_url}/urls",
                headers=self._get_headers(),
                data={"url": url},
            ) as resp:
                if resp.status == 200:
                    return {"checked": True, "malicious_count": 0, "total_engines": 0, "reputation": 0, "findings": ["VT: URL已提交扫描，暂无结果"]}
                return {"checked": False, "malicious_count": 0, "total_engines": 0, "reputation": 0, "findings": []}
        except Exception:
            return {"checked": False, "malicious_count": 0, "total_engines": 0, "reputation": 0, "findings": []}

    async def check_file_hash(self, sha256: str) -> dict:
        """
        异步查询文件哈希的 VirusTotal 信誉

        Returns:
            {
                "checked": bool,
                "malicious_count": int,
                "total_engines": int,
                "link": str,
                "findings": list[str],
            }
        """
        if not self.enabled or not sha256:
            return {"checked": False, "malicious_count": 0, "total_engines": 0, "link": "", "findings": []}

        cache_key = f"file:{sha256}"
        cached = self._get_cached(cache_key)
        if cached:
            logger.info(f"VT 文件哈希缓存命中: {sha256[:16]}...")
            return cached

        try:
            await self._rate_limit_wait()
            async with aiohttp.ClientSession(
                timeout=aiohttp.ClientTimeout(total=VT_TIMEOUT)
            ) as session:
                async with session.get(
                    f"{self.base_url}/files/{sha256}",
                    headers=self._get_headers(),
                ) as resp:
                    if resp.status == 404:
                        result = {"checked": True, "malicious_count": 0, "total_engines": 0, "link": "", "findings": ["VT: 文件未被收录（可能是新文件）"]}
                        self._set_cached(cache_key, result)
                        return result

                    if resp.status != 200:
                        return {"checked": False, "malicious_count": 0, "total_engines": 0, "link": "", "findings": [f"VT查询失败: HTTP {resp.status}"]}

                    data = await resp.json()

            attrs = data.get("data", {}).get("attributes", {})
            last_analysis = attrs.get("last_analysis_results", {})
            malicious_count = sum(1 for v in last_analysis.values() if v.get("category") == "malicious")
            total_engines = len(last_analysis)
            link = f"https://www.virustotal.com/gui/file/{sha256}"

            findings = []
            if malicious_count > 0:
                findings.append(f"VirusTotal: {malicious_count}/{total_engines} 引擎判定为恶意")
            elif total_engines > 0:
                findings.append(f"VirusTotal: {total_engines} 引擎全部判定为安全")
            else:
                findings.append("VT: 文件已收录但无引擎分析结果")

            result = {
                "checked": True,
                "malicious_count": malicious_count,
                "total_engines": total_engines,
                "link": link,
                "findings": findings,
            }

            self._set_cached(cache_key, result)
            logger.info(f"VT 文件哈希查询完成: {sha256[:16]}... -> {malicious_count}/{total_engines} malicious")
            return result

        except asyncio.TimeoutError:
            logger.warning(f"VT 文件哈希查询超时: {sha256[:16]}...")
            return {"checked": False, "malicious_count": 0, "total_engines": 0, "link": "", "findings": ["VT查询超时"]}
        except Exception as e:
            logger.error(f"VT 文件哈希查询异常: {e}")
            return {"checked": False, "malicious_count": 0, "total_engines": 0, "link": "", "findings": [f"VT查询异常: {str(e)}"]}

    # ============================================================
    # 同步兼容接口（用于非异步上下文）
    # ============================================================
    def check_url_sync(self, url: str) -> dict:
        """同步查询 URL 信誉（包装异步方法）"""
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                # 已在事件循环中，用 asyncio.ensure_future 不可行
                # 用 nest_asyncio 或线程池
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as pool:
                    return pool.submit(asyncio.run, self.check_url(url)).result()
            else:
                return asyncio.run(self.check_url(url))
        except RuntimeError:
            return asyncio.run(self.check_url(url))

    def check_file_hash_sync(self, sha256: str) -> dict:
        """同步查询文件哈希信誉（包装异步方法）"""
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as pool:
                    return pool.submit(asyncio.run, self.check_file_hash(sha256)).result()
            else:
                return asyncio.run(self.check_file_hash(sha256))
        except RuntimeError:
            return asyncio.run(self.check_file_hash(sha256))
