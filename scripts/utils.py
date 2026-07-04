#!/usr/bin/env python3
"""
Dependency Skill - 共享工具模块
提供 HTTP 请求、防封禁机制等通用功能
"""

import logging
import random
import time
from typing import Optional, List, Tuple

import httpx
import ua_generator
import semver

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

    def _get_headers(self, accept: str = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8") -> dict:
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
                    response = client.request(method, url, headers=request_headers, **kwargs)
                    response.raise_for_status()
                    self._last_request_time = time.time()
                    return response

            except httpx.HTTPStatusError as e:
                # 429 (Too Many Requests) 是限流，可重试；其他 4xx/5xx 不重试
                if e.response.status_code == 429 and attempt < MAX_RETRIES - 1:
                    time.sleep(2 ** attempt)
                    continue
                raise
            except (httpx.RequestError, httpx.TimeoutException) as e:
                if attempt < MAX_RETRIES - 1:
                    # 重试前稍长延迟
                    time.sleep(2 ** attempt)
                    continue
                raise

        raise httpx.RequestError("Max retries exceeded")

    def get(self, url: str, **kwargs) -> httpx.Response:
        """发送 GET 请求"""
        return self._request("GET", url, **kwargs)


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
        # 清理版本号（移除前缀如 v, =, ^, ~ 等）
        clean_v1 = clean_version_string(v1)
        clean_v2 = clean_version_string(v2)
        
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
    cleaned = cleaned.lstrip('vV')
    cleaned = cleaned.lstrip('=^~')
    cleaned = cleaned.lstrip('><')
    cleaned = cleaned.lstrip('=')
    
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
            clean_v = clean_version_string(v)
            ver = semver.Version.parse(clean_v)
            return (ver.major, ver.minor, ver.patch, ver.prerelease or "", ver.build or "")
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
        
        # 处理复合约束 (逗号分隔)
        if ',' in constraint:
            sub_constraints = [c.strip() for c in constraint.split(',')]
            return all(check_version_constraint(version, c) for c in sub_constraints)
        
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
            return (ver.major == target_ver.major and ver >= target_ver)
        
        # npm 风格的 ~ (兼容次版本)
        elif constraint.startswith("~"):
            target = clean_version_string(constraint[1:])
            target_ver = semver.Version.parse(target)
            return (ver.major == target_ver.major and 
                   ver.minor == target_ver.minor and 
                   ver >= target_ver)
        
        # Python 风格的 ~= (兼容发布)
        elif constraint.startswith("~="):
            target = clean_version_string(constraint[2:])
            target_ver = semver.Version.parse(target)
            # ~=X.Y 意味着 >=X.Y, ==X.*
            return (ver.major == target_ver.major and 
                   ver.minor == target_ver.minor and 
                   ver >= target_ver)
        
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
