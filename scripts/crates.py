#!/usr/bin/env python3
"""
crates.io (Rust) 包查询脚本
支持包详情查询和关键词搜索
"""

from functools import lru_cache
from urllib.parse import quote

from base_ecosystem import BaseEcosystemAdapter
from utils import fetch_json, register_cache


# crates.io 基础 URL
CRATES_API_URL = "https://crates.io/api/v1"
CRATES_BASE_URL = "https://crates.io"


# ============ 缓存（@lru_cache；resolve 模块级 fetch_json 以兼容 patch.object 测试）============
@lru_cache(maxsize=512)
def _fetch_cached(url: str) -> dict:
    return fetch_json(url)


register_cache(_fetch_cached.cache_clear)


def parse_package_info(data: dict) -> dict:
    """
    解析 crates.io API 返回的包数据

    Args:
        data: JSON 数据，格式为:
            {
                "crate": {...},      # 包基本信息
                "versions": [...],    # 版本数组
                "keywords": [...],    # 关键词
                "categories": [...]   # 分类
            }

    Returns:
        包信息字典
    """
    crate = data.get("crate", {})
    name = crate.get("name", "")
    description = crate.get("description", "")

    # 获取版本列表
    versions_data = data.get("versions", [])
    versions = []
    for v in versions_data[:20]:  # 最多20个版本
        versions.append(
            {
                "version": v.get("num", ""),
                "date": v.get("created_at", "")[:10] if v.get("created_at") else "",
            }
        )

    # 获取最新版本信息
    latest_version = crate.get("newest_version", "") or crate.get("max_version", "")

    # 尝试从 versions 数组获取最新版本的许可证
    license = ""
    if versions_data:
        # versions 按时间倒序，第一个是最新的
        license = versions_data[0].get("license", "") if versions_data else ""

    # 弃用信号（R15，零额外请求）：返回的近期版本中存在 yanked 即标记
    deprecated = any(bool(v.get("yanked")) for v in versions_data[:20])

    # 下载 URL
    download_url = f"{CRATES_BASE_URL}/api/v1/crates/{name}"

    # 主页
    homepage = crate.get("homepage", "") or crate.get("documentation", "")

    return {
        "deprecated": deprecated,
        "name": name,
        "description": description,
        "latest_version": latest_version,
        "versions": versions,
        "dependencies": {},  # 依赖需要单独请求 /versions API
        "download_url": download_url,
        "license": license,
        "homepage": homepage,
    }


def parse_search_results(data: dict) -> dict:
    """
    解析 crates.io 搜索 API 返回的数据

    Args:
        data: JSON 数据

    Returns:
        搜索结果字典
    """
    crates = data.get("crates", [])
    meta = data.get("meta", {})
    total = meta.get("total", 0)

    results = []
    for crate in crates[:10]:  # 最多10个结果
        results.append(
            {
                "name": crate.get("name", ""),
                "description": crate.get("description", ""),
                "latest_version": crate.get("newest_version", ""),
                "downloads": crate.get("downloads", 0),
            }
        )

    return {
        "total": total,
        "results": results,
    }


class CratesAdapter(BaseEcosystemAdapter):
    """crates.io 特异逻辑：JSON API。"""

    ECOSYSTEM_NAME = "crates"

    def build_package_url(self, crate_name: str) -> str:
        return f"{CRATES_API_URL}/crates/{quote(crate_name, safe='')}"

    def build_search_url(self, keyword: str) -> str:
        return f"{CRATES_API_URL}/crates?page=1&per_page=10&q={quote(keyword, safe='')}"

    def parse_package_info(self, data: dict, *args) -> dict:
        return parse_package_info(data)

    def parse_search_results(self, data: dict) -> dict:
        return parse_search_results(data)


_adapter = CratesAdapter(fetcher=_fetch_cached)


# ============ 向后兼容模块级 API ============
def get_package(crate_name: str) -> dict:
    """获取 crates.io 包详情（委托 adapter，第二次同 URL 走缓存）。"""
    return _adapter.get_package(crate_name)


def search_packages(keyword: str) -> dict:
    """搜索 crates.io 包（委托 adapter）。"""
    return _adapter.search_packages(keyword)


def main():
    """命令行入口（委托 adapter）。"""
    _adapter.main()


if __name__ == "__main__":
    main()
