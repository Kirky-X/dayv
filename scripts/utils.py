#!/usr/bin/env python3
"""
Dependency Skill - 共享工具模块
提供 HTTP 请求、防封禁机制等通用功能
"""

import logging
import random
import re
import sys
import time
from functools import lru_cache
from typing import Optional, List, Tuple

try:
    import httpx
    import ua_generator
    import semver
except ImportError as _e:
    sys.stderr.write(
        f"错误：缺少依赖 {_e.name}（网络请求/版本解析必需）。\n"
        "请在 skill 根目录执行: pip install -r requirements.txt\n"
    )
    sys.exit(1)

# 配置日志
logger = logging.getLogger(__name__)

# 常量定义
MAX_VERSIONS_DISPLAY = 20
MAX_SEARCH_RESULTS = 10


# 默认超时时间（秒）
DEFAULT_TIMEOUT = 30.0
# 最大重试次数
MAX_RETRIES = 3
# 请求间隔（秒）
MIN_DELAY = 0.5
MAX_DELAY = 2.0


class RequestClient:
    """HTTP 请求客户端，包含防封禁机制"""

    def __init__(self, timeout: float = DEFAULT_TIMEOUT):
        self.timeout = timeout
        self._last_request_time = 0.0

    def _random_delay(self) -> None:
        """请求间随机延迟，防止频率检测"""
        delay = random.uniform(MIN_DELAY, MAX_DELAY)
        time.sleep(delay)

    def _get_headers(
        self,
        accept: str = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    ) -> dict:
        """生成随机浏览器 Headers"""
        ua = str(ua_generator.generate())
        return {
            "User-Agent": ua,
            "Accept": accept,
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
            "Accept-Encoding": "gzip, deflate, br",
            "DNT": "1",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }

    def _request(self, method: str, url: str, **kwargs) -> httpx.Response:
        """
        发送 HTTP 请求，包含重试机制

        Args:
            method: HTTP 方法 (GET, POST, etc.)
            url: 请求 URL
            **kwargs: 其他 httpx 参数

        Returns:
            httpx.Response 对象

        Raises:
            httpx.HTTPError: 请求失败
        """
        headers = kwargs.pop("headers", {})
        timeout = kwargs.pop("timeout", self.timeout)

        for attempt in range(MAX_RETRIES):
            try:
                # 请求间延迟
                self._random_delay()

                # 合并 Headers
                request_headers = self._get_headers()
                request_headers.update(headers)

                with httpx.Client(timeout=timeout, follow_redirects=True) as client:
                    response = client.request(
                        method, url, headers=request_headers, **kwargs
                    )
                    response.raise_for_status()
                    self._last_request_time = time.time()
                    return response

            except httpx.HTTPStatusError as e:
                # 429 (Too Many Requests) 是限流，可重试；其他 4xx/5xx 不重试
                if e.response.status_code == 429 and attempt < MAX_RETRIES - 1:
                    time.sleep(2**attempt)
                    continue
                raise
            except (httpx.RequestError, httpx.TimeoutException) as e:
                if attempt < MAX_RETRIES - 1:
                    # 重试前稍长延迟
                    time.sleep(2**attempt)
                    continue
                raise

        raise httpx.RequestError("Max retries exceeded")

    def get(self, url: str, **kwargs) -> httpx.Response:
        """发送 GET 请求"""
        return self._request("GET", url, **kwargs)

    def post(self, url: str, **kwargs) -> httpx.Response:
        """发送 POST 请求（复用重试 + 随机延迟机制）"""
        return self._request("POST", url, **kwargs)


def fetch_html(url: str, timeout: float = DEFAULT_TIMEOUT) -> str:
    """
    获取 HTML 页面内容

    Args:
        url: 页面 URL
        timeout: 超时时间（秒）

    Returns:
        HTML 内容字符串

    Raises:
        httpx.HTTPError: 请求失败
    """
    client = RequestClient(timeout)
    response = client.get(url)
    return response.text


def fetch_json(url: str, timeout: float = DEFAULT_TIMEOUT) -> dict:
    """
    获取 JSON 数据

    Args:
        url: API URL
        timeout: 超时时间（秒）

    Returns:
        JSON 解析后的字典

    Raises:
        httpx.HTTPError: 请求失败
    """
    client = RequestClient(timeout)
    headers = {"Accept": "application/json"}
    response = client.get(url, headers=headers)
    return response.json()


# 缓存上限（同会话内 URL 维度去重，减少重复 registry 请求）
_FETCH_CACHE_MAXSIZE = 512


@lru_cache(maxsize=_FETCH_CACHE_MAXSIZE)
def fetch_json_cached(url: str) -> dict:
    """lru_cache 版 fetch_json（按 URL 缓存，默认 timeout）。

    适用于包元数据查询（同会话内 URL 返回值不变）。返回的 dict 必须视为只读——
    多处共享同一对象，修改会污染缓存。需要自定义 timeout 或跳过缓存请用 fetch_json。
    """
    return fetch_json(url)


@lru_cache(maxsize=_FETCH_CACHE_MAXSIZE)
def fetch_html_cached(url: str) -> str:
    """lru_cache 版 fetch_html（按 URL 缓存，默认 timeout）。"""
    return fetch_html(url)


# ============ 缓存注册表（测试隔离用）============
# 各 ecosystem 子脚本 import 时 register_cache(_fetch_cached.cache_clear)，
# clear_fetch_cache() 一次性清空全部 lru_cache，避免跨用例污染（缓存命中干扰 fetch 计数断言）。
_CACHE_CLEARERS: List = []


def register_cache(clear_fn) -> None:
    """注册一个 lru_cache 的 cache_clear 回调（子脚本 import 时调用）。

    Args:
        clear_fn: 通常是某 @lru_cache 函数的 .cache_clear 绑定方法。
    """
    if clear_fn not in _CACHE_CLEARERS:
        _CACHE_CLEARERS.append(clear_fn)


def clear_fetch_cache() -> None:
    """清空所有已注册的 fetch lru_cache（utils 内置 + 7 个 ecosystem 子脚本）。

    主要供测试在用例间调用，避免上一用例的缓存命中干扰下一用例的 fetch 计数断言。
    """
    fetch_json_cached.cache_clear()
    fetch_html_cached.cache_clear()
    for clear_fn in _CACHE_CLEARERS:
        try:
            clear_fn()
        except Exception:
            logger.debug("清理 fetch 缓存失败", exc_info=True)


# 说明：原 fetch_json_concurrent（4 线程并发 fetch）已删除——无任何调用方，
# 且与 anti-patterns.md 的「并发红线：串行调用」直接矛盾（规则8/21）。


def safe_get(data: dict, *keys, default: str = "") -> str:
    """
    安全获取嵌套字典值

    Args:
        data: 字典数据
        keys: 嵌套键列表
        default: 默认值

    Returns:
        获取的值或默认值
    """
    result = data
    for key in keys:
        if isinstance(result, dict):
            result = result.get(key)
            if result is None:
                return default
        else:
            return default
    return result if result is not None else default


# 1-2 段纯数字版本（"9.9"、"10"）：semver 严格要求三段，直接 parse 会失败并
# 跌回字符串比较（"9.9" > "10.0"），补零归一到三段后再比较
_PARTIAL_NUMERIC_RE = re.compile(r"^(\d+)(?:\.(\d+))?$")
# npm 通配段：1.2.x / 1.x / 1.2.* / 单独 * 或 x
_WILDCARD_RE = re.compile(r"^(\d+(?:\.\d+)*)\.(?:x|X|\*)$")
_ANY_VERSION_RE = re.compile(r"^(?:\*|x|X)$")
# npm hyphen 区间：A - B（两侧必须有空格），任意一侧可为 1-2 段缺段版本
_HYPHEN_SPLIT_RE = re.compile(r"\s-\s")


def _pad_semver(version: str) -> str:
    """把 1-2 段纯数字版本补齐为三段（"9.9" → "9.9.0"），其余原样返回。"""
    m = _PARTIAL_NUMERIC_RE.match(version)
    if not m:
        return version
    return f"{m.group(1)}.{m.group(2) or '0'}.0"


def compare_versions(v1: str, v2: str) -> int:
    """
    比较两个语义化版本号

    Args:
        v1: 版本号1 (如 "1.2.3")
        v2: 版本号2 (如 "1.3.0")

    Returns:
        -1: v1 < v2
         0: v1 == v2
         1: v1 > v2
    """
    try:
        # 清理版本号（移除前缀如 v, =, ^, ~ 等），1-2 段补零归一
        clean_v1 = _pad_semver(clean_version_string(v1))
        clean_v2 = _pad_semver(clean_version_string(v2))

        ver1 = semver.Version.parse(clean_v1)
        ver2 = semver.Version.parse(clean_v2)

        if ver1 < ver2:
            return -1
        elif ver1 > ver2:
            return 1
        else:
            return 0
    except (ValueError, TypeError) as e:
        # 如果解析失败，回退到字符串比较
        return -1 if v1 < v2 else (1 if v1 > v2 else 0)


def clean_version_string(version: str) -> str:
    """
    清理版本号字符串，移除常见前缀和后缀

    Args:
        version: 原始版本号字符串

    Returns:
        清理后的版本号
    """
    if not version:
        return ""

    # 移除常见前缀: v, =, ^, ~, >=, <=, >, <
    cleaned = version.strip()
    cleaned = cleaned.lstrip("vV")
    cleaned = cleaned.lstrip("=^~")
    cleaned = cleaned.lstrip("><")
    cleaned = cleaned.lstrip("=")

    return cleaned


def is_valid_semver(version: str) -> bool:
    """
    检查版本号是否为有效的语义化版本

    Args:
        version: 版本号字符串

    Returns:
        True 如果是有效的 semver
    """
    try:
        clean_version = clean_version_string(version)
        semver.Version.parse(clean_version)
        return True
    except (ValueError, TypeError):
        return False


def sort_versions(versions: List[str], reverse: bool = True) -> List[str]:
    """
    对版本号列表进行语义化排序

    Args:
        versions: 版本号列表
        reverse: True 为降序（最新版本在前），False 为升序

    Returns:
        排序后的版本号列表
    """

    def version_key(v):
        try:
            clean_v = _pad_semver(clean_version_string(v))
            ver = semver.Version.parse(clean_v)
            return (
                ver.major,
                ver.minor,
                ver.patch,
                ver.prerelease or "",
                ver.build or "",
            )
        except (ValueError, TypeError):
            # 无效版本号排在最后
            return (-1, -1, -1, "", "")

    return sorted(versions, key=version_key, reverse=reverse)


def check_version_constraint(version: str, constraint: str) -> bool:
    """
    检查版本是否满足约束条件

    Args:
        version: 版本号 (如 "1.2.3")
        constraint: 约束条件 (如 ">=1.0.0", "^1.2.0", "~1.2.0", ">=1.0.0,<2.0.0")

    Returns:
        True 如果满足约束
    """
    try:
        clean_ver = clean_version_string(version)
        ver = semver.Version.parse(clean_ver)

        # 解析约束
        constraint = constraint.strip()

        # npm 通配：单独 * / x 匹配任意版本
        if _ANY_VERSION_RE.match(constraint):
            return True

        # 处理复合约束 (逗号分隔)
        if "," in constraint:
            sub_constraints = [c.strip() for c in constraint.split(",")]
            return all(check_version_constraint(version, c) for c in sub_constraints)

        # npm hyphen 区间 "A - B"：下界含（缺段补 0）、上界按 npm 缺段语义
        # （"2.3" → < 2.4.0；"2" → < 3.0.0；完整三段 → <= 上界）
        if _HYPHEN_SPLIT_RE.search(constraint):
            left, right = _HYPHEN_SPLIT_RE.split(constraint, maxsplit=1)
            lower = semver.Version.parse(_pad_semver(clean_version_string(left.strip())))
            right_clean = clean_version_string(right.strip())
            segs = right_clean.split(".")
            if len(segs) == 1:
                return ver >= lower and ver < semver.Version.parse(
                    f"{int(segs[0]) + 1}.0.0"
                )
            if len(segs) == 2:
                return ver >= lower and ver < semver.Version.parse(
                    f"{segs[0]}.{int(segs[1]) + 1}.0"
                )
            return ver >= lower and ver <= semver.Version.parse(_pad_semver(right_clean))

        # 精确匹配
        if constraint.startswith("=") and not constraint.startswith("=="):
            target = clean_version_string(constraint[1:])
            return ver == semver.Version.parse(target)

        # 范围匹配 (>=, <=, >, <, ==)
        if constraint.startswith(">="):
            target = clean_version_string(constraint[2:])
            return ver >= semver.Version.parse(target)
        elif constraint.startswith("<="):
            target = clean_version_string(constraint[2:])
            return ver <= semver.Version.parse(target)
        elif constraint.startswith(">"):
            target = clean_version_string(constraint[1:])
            return ver > semver.Version.parse(target)
        elif constraint.startswith("<"):
            target = clean_version_string(constraint[1:])
            return ver < semver.Version.parse(target)
        elif constraint.startswith("=="):
            target = clean_version_string(constraint[2:])
            return ver == semver.Version.parse(target)
        elif constraint.startswith("!="):
            target = clean_version_string(constraint[2:])
            return ver != semver.Version.parse(target)

        # npm 风格的 ^ (兼容主版本)
        elif constraint.startswith("^"):
            target = clean_version_string(constraint[1:])
            target_ver = semver.Version.parse(target)
            return ver.major == target_ver.major and ver >= target_ver

        # npm 风格的 ~ (兼容次版本)
        elif constraint.startswith("~"):
            target = clean_version_string(constraint[1:])
            target_ver = semver.Version.parse(target)
            return (
                ver.major == target_ver.major
                and ver.minor == target_ver.minor
                and ver >= target_ver
            )

        # Python 风格的 ~= (兼容发布)
        elif constraint.startswith("~="):
            target = clean_version_string(constraint[2:])
            target_ver = semver.Version.parse(target)
            # ~=X.Y 意味着 >=X.Y, ==X.*
            return (
                ver.major == target_ver.major
                and ver.minor == target_ver.minor
                and ver >= target_ver
            )

        # npm 通配后缀：1.2.x / 1.x / 1.2.*（按数字前缀逐段匹配）
        elif _WILDCARD_RE.match(constraint):
            prefix_segs = [
                int(s) for s in _WILDCARD_RE.match(constraint).group(1).split(".")
            ]
            ver_segs = [ver.major, ver.minor, ver.patch]
            return all(v == p for v, p in zip(ver_segs, prefix_segs))

        # 精确匹配（无前缀）
        else:
            target = clean_version_string(constraint)
            return ver == semver.Version.parse(target)

    except (ValueError, TypeError):
        return False


def find_latest_version(versions: List[str], constraint: str = None) -> Optional[str]:
    """
    查找满足约束的最新版本

    Args:
        versions: 版本号列表
        constraint: 可选的约束条件

    Returns:
        满足约束的最新版本，如果没有则返回 None
    """
    # 先排序
    sorted_versions = sort_versions(versions, reverse=True)

    if not constraint:
        return sorted_versions[0] if sorted_versions else None

    # 查找第一个满足约束的版本
    for version in sorted_versions:
        if check_version_constraint(version, constraint):
            return version

    return None
