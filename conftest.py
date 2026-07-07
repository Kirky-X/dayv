"""
Pytest 全局配置（dayv skill 根目录）。

1. 把 scripts/ 加入 sys.path，便于 tests/ 与 scripts/tests/ 直接 import ecosystem 模块。
2. autouse fixture：每个用例前后清空所有 fetch lru_cache，避免跨用例缓存污染
   （例如上一定用例缓存了 get_package("rails")，下一用例 patch fetch_json 时
   会因缓存命中而拿不到调用计数）。对应 utils.clear_fetch_cache()。
"""

import os
import sys

_ROOT = os.path.dirname(os.path.abspath(__file__))
_SCRIPTS = os.path.join(_ROOT, "scripts")
if _SCRIPTS not in sys.path:
    sys.path.insert(0, _SCRIPTS)

import pytest  # noqa: E402

try:
    from utils import clear_fetch_cache
except Exception:  # pragma: no cover - utils 缺失时仍允许收集
    clear_fetch_cache = None


@pytest.fixture(autouse=True)
def _clear_fetch_caches_each_test():
    """每个测试用例前后清空 fetch lru_cache，保证 fetch 计数断言可靠。"""
    if clear_fetch_cache is not None:
        clear_fetch_cache()
    yield
    if clear_fetch_cache is not None:
        clear_fetch_cache()
