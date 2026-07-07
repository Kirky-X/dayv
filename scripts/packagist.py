#!/usr/bin/env python3
"""
Packagist (PHP) 包查询脚本
支持包详情查询和关键词搜索
API 文档: https://packagist.org/apidoc
包名格式: vendor/package (如: monolog/monolog)
"""

from functools import lru_cache
from urllib.parse import quote

from base_ecosystem import BaseEcosystemAdapter
from utils import fetch_json, register_cache


# Packagist API 基础 URL
PACKAGIST_REPO_URL = "https://repo.packagist.org"
PACKAGIST_BASE_URL = "https://packagist.org"


# ============ 缓存（@lru_cache；resolve 模块级 fetch_json 以兼容 patch.object 测试）============
@lru_cache(maxsize=512)
def _fetch_cached(url: str) -> dict:
    return fetch_json(url)


register_cache(_fetch_cached.cache_clear)


def parse_package_info(data: dict, package_name: str) -> dict:
    """
    解析 Packagist /p2/{vendor}/{package}.json 返回的包数据

    Packagist p2 API 返回结构：
        {
            "packages": {
                "monolog/monolog": [ {version_dict}, {version_dict}, ... ]
            },
            "minified": "composer/2.0"
        }
    数组按版本倒序排列（最新在前）。

    Args:
        data: JSON 数据
        package_name: 包名 (vendor/package)

    Returns:
        统一格式包信息字典
    """
    packages_dict = data.get("packages", {})
    version_list = packages_dict.get(package_name, [])

    if not version_list:
        return {
            "name": package_name,
            "description": "",
            "latest_version": "",
            "versions": [],
            "dependencies": {},
            "download_url": f"{PACKAGIST_BASE_URL}/packages/{package_name}",
            "license": "",
            "homepage": "",
        }

    # 最新版本（数组第一个）
    latest = version_list[0]
    description = latest.get("description", "")
    latest_version = latest.get("version", "")
    license = ""
    licenses = latest.get("license", [])
    if licenses:
        license = licenses[0]
    homepage = latest.get("homepage", "")

    # 版本列表（最多 20 个）
    versions = []
    for v in version_list[:20]:
        time_str = v.get("time", "")
        date = time_str[:10] if time_str else ""
        versions.append({"version": v.get("version", ""), "date": date})

    # 依赖（从最新版本的 require 字段提取）
    dependencies = latest.get("require", {})
    if not isinstance(dependencies, dict):
        dependencies = {}

    download_url = f"{PACKAGIST_BASE_URL}/packages/{package_name}"

    return {
        "name": package_name,
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
    解析 Packagist /search.json?q=xxx 返回的搜索结果

    Args:
        data: JSON 数据

    Returns:
        统一格式搜索结果字典
    """
    results = []
    raw_results = data.get("results", [])
    for pkg in raw_results[:10]:
        # Packagist search API 不直接返回 latest_version，用 url 字段占位
        results.append(
            {
                "name": pkg.get("name", ""),
                "description": pkg.get("description", ""),
                "latest_version": "",
            }
        )

    total = data.get("total", len(results))
    return {
        "total": total,
        "results": results,
    }


class PackagistAdapter(BaseEcosystemAdapter):
    """Packagist 特异逻辑：p2 JSON API + vendor/package 双段名校验。"""

    ECOSYSTEM_NAME = "packagist"
    PACKAGE_USAGE_HINT = "<vendor/package>"
    PACKAGE_FORMAT_ERROR = "Packagist 包名格式为 vendor/package (如 monolog/monolog)"

    def validate_package_arg(self, arg: str) -> bool:
        return "/" in arg

    def build_package_url(self, package_name: str) -> str:
        # package_name 形如 "monolog/monolog"，safe='/' 保留分隔符
        return f"{PACKAGIST_REPO_URL}/p2/{quote(package_name, safe='/')}.json"

    def build_search_url(self, keyword: str) -> str:
        return f"{PACKAGIST_BASE_URL}/search.json?q={quote(keyword)}"

    def parse_package_info(self, data: dict, package_name: str) -> dict:
        return parse_package_info(data, package_name)

    def parse_search_results(self, data: dict) -> dict:
        return parse_search_results(data)


_adapter = PackagistAdapter(fetcher=_fetch_cached)


# ============ 向后兼容模块级 API ============
def get_package(package_name: str) -> dict:
    """获取 Packagist 包详情（委托 adapter，第二次同 URL 走缓存）。"""
    return _adapter.get_package(package_name)


def search_packages(keyword: str) -> dict:
    """搜索 Packagist 包（委托 adapter）。"""
    return _adapter.search_packages(keyword)


def main():
    """命令行入口（委托 adapter）。"""
    _adapter.main()


if __name__ == "__main__":
    main()
