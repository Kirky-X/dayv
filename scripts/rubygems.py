#!/usr/bin/env python3
"""
RubyGems (Ruby) 包查询脚本
支持包详情查询和关键词搜索
API 文档: https://guides.rubygems.org/rubygems-org-api/
"""

import json
import sys
from typing import Optional
from urllib.parse import quote

from utils import fetch_json


# RubyGems API 基础 URL
RUBYGEMS_API_URL = "https://rubygems.org/api/v1"


def parse_package_info(data: dict) -> dict:
    """
    解析 RubyGems API /api/v1/gems/{name}.json 返回的包数据

    Args:
        data: JSON 数据

    Returns:
        统一格式包信息字典
    """
    name = data.get("name", "")
    description = data.get("info", "")
    latest_version = data.get("version", "")
    license = ""
    licenses = data.get("licenses", [])
    if licenses:
        license = licenses[0]

    homepage = data.get("homepage_uri", "")
    project_uri = data.get("project_uri", "")
    download_url = project_uri or f"{RUBYGEMS_API_URL}/gems/{name}.json"

    # RubyGems 单个 gem API 不返回版本历史，仅返回当前版本
    versions = []
    if latest_version:
        versions.append({"version": latest_version, "date": ""})

    # 解析依赖：{"runtime": [{"name":..., "requirements":...}], "development": [...]}
    dependencies = {}
    deps_data = data.get("dependencies", {})
    for dep_type in ("runtime", "development"):
        for dep in deps_data.get(dep_type, []):
            dep_name = dep.get("name", "")
            dep_req = dep.get("requirements", "*")
            if dep_name:
                dependencies[dep_name] = dep_req

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


def parse_search_results(data: list) -> dict:
    """
    解析 RubyGems /api/v1/search.json?query=xxx 返回的搜索结果

    Args:
        data: JSON 数组

    Returns:
        统一格式搜索结果字典
    """
    results = []
    # data 是 list，最多取 10 个
    for gem in data[:10]:
        results.append({
            "name": gem.get("name", ""),
            "description": gem.get("info", ""),
            "latest_version": gem.get("version", ""),
        })

    return {
        "total": len(results),
        "results": results,
    }


def get_package(gem_name: str) -> dict:
    """
    获取 RubyGems 包详情

    Args:
        gem_name: gem 名称

    Returns:
        包信息字典
    """
    url = f"{RUBYGEMS_API_URL}/gems/{quote(gem_name)}.json"
    data = fetch_json(url)
    return parse_package_info(data)


def search_packages(keyword: str) -> dict:
    """
    搜索 RubyGems 包

    Args:
        keyword: 搜索关键词

    Returns:
        搜索结果字典
    """
    url = f"{RUBYGEMS_API_URL}/search.json?query={quote(keyword)}"
    data = fetch_json(url)
    return parse_search_results(data)


def main():
    """命令行入口"""
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python rubygems.py <gem-name>       # 查询包详情")
        print("  python rubygems.py --search <keyword>  # 搜索包")
        sys.exit(1)

    if sys.argv[1] == "--search":
        if len(sys.argv) < 3:
            print("Error: 请提供搜索关键词")
            sys.exit(1)
        keyword = sys.argv[2]
        result = search_packages(keyword)
    else:
        gem_name = sys.argv[1]
        result = get_package(gem_name)

    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
