#!/usr/bin/env python3
"""
npm 包查询脚本
支持包详情查询和关键词搜索
"""

import json
import sys
from typing import Optional

from bs4 import BeautifulSoup

from utils import fetch_html, fetch_json


# npm 基础 URL
NPM_REGISTRY_URL = "https://registry.npmjs.org"
NPM_SEARCH_URL = "https://www.npmjs.com"


def parse_package_info(data: dict) -> dict:
    """
    解析 npm registry API 返回的包数据

    Args:
        data: JSON 数据

    Returns:
        包信息字典
    """
    name = data.get("name", "")
    latest = data.get("dist-tags", {}).get("latest", "")
    versions_data = data.get("versions", {})

    # 获取最新版本的依赖
    dependencies = {}
    if latest in versions_data:
        latest_info = versions_data[latest]
        dependencies = latest_info.get("dependencies", {})

    # 获取版本列表 (最近10个)
    versions_list = list(versions_data.keys())[-10:]
    versions = []
    for v in reversed(versions_list):
        time_str = data.get("time", {}).get(v, "")
        date = time_str[:10] if time_str else ""  # 取日期部分
        versions.append({"version": v, "date": date})

    # 获取描述
    description = data.get("description", "")

    # 获取许可证
    license = data.get("license", "")

    # 获取主页
    homepage = data.get("homepage", "")

    # 下载 URL
    if latest in versions_data:
        download_url = versions_data[latest].get("dist", {}).get("tarball", "")
    else:
        download_url = f"{NPM_REGISTRY_URL}/{name}/-/{name}-{latest}.tgz"

    return {
        "name": name,
        "description": description,
        "latest_version": latest,
        "versions": versions,
        "dependencies": dependencies,
        "download_url": download_url,
        "license": license,
        "homepage": homepage,
    }


def parse_search_results_json(data: dict) -> dict:
    """
    解析 npm 搜索 API 返回的 JSON 数据

    Args:
        data: JSON 数据

    Returns:
        搜索结果字典
    """
    results = []
    objects = data.get("objects", [])

    for obj in objects[:10]:
        package = obj.get("package", {})
        results.append({
            "name": package.get("name", ""),
            "description": package.get("description", ""),
            "latest_version": package.get("version", ""),
        })

    total = data.get("total", len(results))
    return {
        "total": total,
        "results": results,
    }


def get_package(package_name: str) -> dict:
    """
    获取 npm 包详情

    Args:
        package_name: 包名称

    Returns:
        包信息字典
    """
    url = f"{NPM_REGISTRY_URL}/{package_name}"
    data = fetch_json(url)
    return parse_package_info(data)


def search_packages(keyword: str) -> dict:
    """
    搜索 npm 包

    Args:
        keyword: 搜索关键词

    Returns:
        搜索结果字典
    """
    # 使用 npm registry 搜索 API (免费，无需认证)
    url = f"{NPM_REGISTRY_URL}/-/v1/search"
    params = {"text": keyword, "size": 10}
    full_url = f"{url}?text={keyword}&size=10"
    data = fetch_json(full_url)
    return parse_search_results_json(data)


def main():
    """命令行入口"""
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python npm.py <package-name>       # 查询包详情")
        print("  python npm.py --search <keyword>   # 搜索包")
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
