#!/usr/bin/env python3
"""
NuGet (.NET) 包查询脚本
支持包详情查询和关键词搜索
API 文档: https://learn.microsoft.com/nuget/api/overview
NuGet V3 API 要求 package id 在 URL 中全小写。
"""

from functools import lru_cache
from urllib.parse import quote

from base_ecosystem import BaseEcosystemAdapter
from utils import fetch_json, register_cache


# NuGet API 基础 URL
NUGET_REGISTRATION_URL = "https://api.nuget.org/v3/registration5-gz-semver2"
NUGET_SEARCH_URL = "https://azuresearch-usnc.nuget.org"


# ============ 缓存（@lru_cache；resolve 模块级 fetch_json 以兼容 patch.object 测试）============
@lru_cache(maxsize=512)
def _fetch_cached(url: str) -> dict:
    return fetch_json(url)


register_cache(_fetch_cached.cache_clear)


def parse_package_info(data: dict) -> dict:
    """
    解析 NuGet V3 registration5-gz-semver2 index.json 返回的包数据

    NuGet registration index 结构：
        {
            "items": [
                {
                    "items": [
                        {
                            "catalogEntry": {
                                "id": "Newtonsoft.Json",  # 原始大小写
                                "version": "13.0.3",
                                "description": "...",
                                "licenseExpression": "MIT",
                                "projectUrl": "...",
                                "published": "...",
                                "dependencyGroups": [...]
                            }
                        }
                    ],
                    "upper": "13.0.3",
                    "lower": "13.0.3"
                }
            ]
        }

    Args:
        data: JSON 数据

    Returns:
        统一格式包信息字典（name 保留原始大小写）
    """
    name = ""
    description = ""
    latest_version = ""
    license = ""
    homepage = ""
    dependencies = {}
    versions = []

    items_pages = data.get("items", [])

    # 遍历每个 page，提取 leaf items 的 catalogEntry
    for page in items_pages:
        leaf_items = page.get("items", [])
        for leaf in leaf_items:
            catalog_entry = leaf.get("catalogEntry", {})
            entry_id = catalog_entry.get("id", "")
            if not name and entry_id:
                name = entry_id  # 第一次填充保留原始大小写

            version = catalog_entry.get("version", "")
            published = catalog_entry.get("published", "")
            date = published[:10] if published else ""

            versions.append({"version": version, "date": date})

            # 第一个 leaf（最新版本）填充主字段
            if not latest_version and version:
                latest_version = version
                description = catalog_entry.get("description", "")
                license = catalog_entry.get(
                    "licenseExpression", ""
                ) or catalog_entry.get("licenseUrl", "")
                homepage = catalog_entry.get("projectUrl", "")
                # 提取依赖
                dep_groups = catalog_entry.get("dependencyGroups", [])
                for group in dep_groups:
                    deps = group.get("dependencies", [])
                    for d in deps:
                        dep_id = d.get("id", "")
                        dep_range = d.get("range", "*")
                        if dep_id:
                            dependencies[dep_id] = dep_range

    # 限制最多 20 个版本
    versions = versions[:20]

    download_url = f"{NUGET_REGISTRATION_URL}/{name.lower()}/index.json" if name else ""

    return {
        "name": name,
        "description": description,
        "latest_version": latest_version,
        "versions": versions,
        "dependencies": dependencies,
        "download_url": download_url,
        "license": license,
        "homepage": homepage,
    }


def parse_search_results(data: dict) -> dict:
    """
    解析 NuGet search API /query?q=xxx 返回的搜索结果

    Args:
        data: JSON 数据

    Returns:
        统一格式搜索结果字典
    """
    results = []
    raw_data = data.get("data", [])
    for pkg in raw_data[:10]:
        results.append(
            {
                "name": pkg.get("id", ""),
                "description": pkg.get("description", ""),
                "latest_version": pkg.get("version", ""),
            }
        )

    total = data.get("totalHits", len(results))
    return {
        "total": total,
        "results": results,
    }


class NuGetAdapter(BaseEcosystemAdapter):
    """NuGet 特异逻辑：V3 registration JSON API，URL 中 package id 必须全小写。"""

    ECOSYSTEM_NAME = "nuget"

    def build_package_url(self, package_name: str) -> str:
        # URL 中强制小写并 URL encode（NuGet V3 API 要求 package id 全小写）；
        # 原始大小写由 parse_package_info 从响应 catalogEntry.id 还原
        encoded_name = quote(package_name.lower(), safe="")
        return f"{NUGET_REGISTRATION_URL}/{encoded_name}/index.json"

    def build_search_url(self, keyword: str) -> str:
        return f"{NUGET_SEARCH_URL}/query?q={quote(keyword, safe='')}"

    def parse_package_info(self, data: dict, *args) -> dict:
        return parse_package_info(data)

    def parse_search_results(self, data: dict) -> dict:
        return parse_search_results(data)


_adapter = NuGetAdapter(fetcher=_fetch_cached)


# ============ 向后兼容模块级 API ============
def get_package(package_name: str) -> dict:
    """获取 NuGet 包详情（委托 adapter，第二次同 URL 走缓存；name 保留原始大小写）。"""
    return _adapter.get_package(package_name)


def search_packages(keyword: str) -> dict:
    """搜索 NuGet 包（委托 adapter）。"""
    return _adapter.search_packages(keyword)


def main():
    """命令行入口（委托 adapter）。"""
    _adapter.main()


if __name__ == "__main__":
    main()
