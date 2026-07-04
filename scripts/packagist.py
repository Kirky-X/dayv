#!/usr/bin/env python3
"""
Packagist (PHP) 包查询脚本
支持包详情查询和关键词搜索
API 文档: https://packagist.org/apidoc
包名格式: vendor/package (如: monolog/monolog)
"""

import json
import sys
from typing import Optional
from urllib.parse import quote

from utils import fetch_json


# Packagist API 基础 URL
PACKAGIST_REPO_URL = "https://repo.packagist.org"
PACKAGIST_BASE_URL = "https://packagist.org"


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
        results.append({
            "name": pkg.get("name", ""),
            "description": pkg.get("description", ""),
            "latest_version": "",
        })

    total = data.get("total", len(results))
    return {
        "total": total,
        "results": results,
    }


def get_package(package_name: str) -> dict:
    """
    获取 Packagist 包详情

    Args:
        package_name: 包名 (vendor/package，如 monolog/monolog)

    Returns:
        包信息字典
    """
    # package_name 形如 "monolog/monolog"，URL 拼接
    url = f"{PACKAGIST_REPO_URL}/p2/{quote(package_name, safe='/')}.json"
    data = fetch_json(url)
    return parse_package_info(data, package_name)


def search_packages(keyword: str) -> dict:
    """
    搜索 Packagist 包

    Args:
        keyword: 搜索关键词

    Returns:
        搜索结果字典
    """
    url = f"{PACKAGIST_BASE_URL}/search.json?q={quote(keyword)}"
    data = fetch_json(url)
    return parse_search_results(data)


def main():
    """命令行入口"""
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python packagist.py <vendor/package>       # 查询包详情")
        print("  python packagist.py --search <keyword>     # 搜索包")
        sys.exit(1)

    if sys.argv[1] == "--search":
        if len(sys.argv) < 3:
            print("Error: 请提供搜索关键词")
            sys.exit(1)
        keyword = sys.argv[2]
        result = search_packages(keyword)
    else:
        package_name = sys.argv[1]
        if "/" not in package_name:
            print("Error: Packagist 包名格式为 vendor/package (如 monolog/monolog)")
            sys.exit(1)
        result = get_package(package_name)

    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
