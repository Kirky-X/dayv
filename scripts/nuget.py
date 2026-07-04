#!/usr/bin/env python3
"""
NuGet (.NET) 包查询脚本
支持包详情查询和关键词搜索
API 文档: https://learn.microsoft.com/nuget/api/overview
NuGet V3 API 要求 package id 在 URL 中全小写。
"""

import json
import sys
from typing import Optional
from urllib.parse import quote

from utils import fetch_json


# NuGet API 基础 URL
NUGET_REGISTRATION_URL = "https://api.nuget.org/v3/registration5-gz-semver2"
NUGET_SEARCH_URL = "https://azuresearch-usnc.nuget.org"


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
                license = catalog_entry.get("licenseExpression", "") or catalog_entry.get("licenseUrl", "")
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
        results.append({
            "name": pkg.get("id", ""),
            "description": pkg.get("description", ""),
            "latest_version": pkg.get("version", ""),
        })

    total = data.get("totalHits", len(results))
    return {
        "total": total,
        "results": results,
    }


def get_package(package_name: str) -> dict:
    """
    获取 NuGet 包详情

    NuGet V3 API 要求 package id 在 URL 中全小写。

    Args:
        package_name: 包名（用户可传任意大小写）

    Returns:
        包信息字典（name 保留原始大小写）
    """
    # URL 中强制小写并 URL encode（NuGet V3 API 要求 package id 全小写）
    encoded_name = quote(package_name.lower(), safe='')
    url = f"{NUGET_REGISTRATION_URL}/{encoded_name}/index.json"
    data = fetch_json(url)
    return parse_package_info(data)


def search_packages(keyword: str) -> dict:
    """
    搜索 NuGet 包

    Args:
        keyword: 搜索关键词

    Returns:
        搜索结果字典
    """
    url = f"{NUGET_SEARCH_URL}/query?q={quote(keyword, safe='')}"
    data = fetch_json(url)
    return parse_search_results(data)


def main():
    """命令行入口"""
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python nuget.py <package-id>       # 查询包详情")
        print("  python nuget.py --search <keyword>  # 搜索包")
        sys.exit(1)

    if sys.argv[1] == "--search":
        if len(sys.argv) < 3:
            print("Error: 请提供搜索关键词")
            sys.exit(1)
        keyword = sys.argv[2]
        result = search_packages(keyword)
    else:
        package_name = sys.argv[1]
        result = get_package(package_name)

    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
