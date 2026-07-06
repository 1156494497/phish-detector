"""
检测结果缓存

用文件内容的 sha256 当 key，把整套 DetectionResult 缓存在内存里。
目的：同一封邮件先 /api/analyze 再 /api/report 时，不必把解析+三 analyzer
+ LLM + VT 再跑一遍（原本要跑两遍）。

设计取舍：
  - 内存缓存（LRU + TTL），不引外部依赖；进程重启即失效，可接受
  - 只缓存 detection_result（Pydantic 对象）和 parsed 包装，不缓存 HTML 报告
    （报告生成很轻；结果不变即报告可重现）
  - 缓存命中不区分 analyzing/report 两种用途——同一文件两路复用同一个结果
"""
import hashlib
import time
from collections import OrderedDict
from threading import Lock
from typing import Any, Optional


class ResultCache:
    """带 TTL 与容量上限的 LRU 缓存，key = sha256(文件内容bytes)"""

    def __init__(self, max_entries: int = 200, ttl: float = 3600.0):
        self._store: "OrderedDict[str, tuple[float, Any]]" = OrderedDict()
        self._lock = Lock()
        self.max_entries = max_entries
        self.ttl = ttl
        # 简易统计
        self.hits = 0
        self.misses = 0

    @staticmethod
    def make_key(data: bytes) -> str:
        """用文件内容算哈希做 key（与文件名无关，避免重命名/编码差异）"""
        return hashlib.sha256(data).hexdigest()

    def get(self, data: bytes) -> Optional[Any]:
        key = self.make_key(data)
        with self._lock:
            item = self._store.get(key)
            if item is None:
                self.misses += 1
                return None
            ts, value = item
            if time.time() - ts > self.ttl:
                # 过期，清理
                self._store.pop(key, None)
                self.misses += 1
                return None
            # 命中：移到末尾（LRU）
            self._store.move_to_end(key)
            self.hits += 1
            return value

    def put(self, data: bytes, value: Any) -> None:
        key = self.make_key(data)
        with self._lock:
            self._store[key] = (time.time(), value)
            self._store.move_to_end(key)
            # 容量上限：淘汰最老
            while len(self._store) > self.max_entries:
                self._store.popitem(last=False)

    def stats(self) -> dict:
        with self._lock:
            return {"entries": len(self._store), "hits": self.hits, "misses": self.misses,
                    "max_entries": self.max_entries, "ttl": self.ttl}

    def clear(self) -> None:
        with self._lock:
            self._store.clear()
            self.hits = 0
            self.misses = 0


# 全局单例
result_cache = ResultCache(max_entries=200, ttl=3600)