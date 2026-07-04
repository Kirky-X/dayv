#!/usr/bin/env python3
"""
crates.io (Rust) 包查询脚本
支持包详情查询和关键词搜索
"""

import json
import sys
from typing import Optional

from bs4 import BeautifulSoup

from utils import fetch_html, fetch_json


# crates.io 基础 URL
CRATES_API_URL = "https://crates.io/api/v1"
CRATES_BASE_URL = "https://crates.io"


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
        versions.append({
            "version": v.get("num", ""),
            "date": v.get("created_at", "")[:10] if v.get("created_at") else "",
        })

    # 获取最新版本信息
    latest_version = crate.get("newest_version", "") or crate.get("max_version", "")

    # 尝试从 versions 数组获取最新版本的许可证
    license = ""
    if versions_data:
        # versions 按时间倒序，第一个是最新的
        license = versions_data[0].get("license", "") if versions_data else ""

    # 下载 URL
    download_url = f"{CRATES_BASE_URL}/api/v1/crates/{name}"

    # 主页
    homepage = crate.get("homepage", "") or crate.get("documentation", "")

    # 总下载量
    downloads = crate.get("downloads", 0)

    return {
        "name": name,
        "description": description,
        "latest_version": latest_version,
        "versions": versions,
        "dependencies": {},  # 依赖需要单独请求 /versions API
        "download_url": download_url,
        "license": license,
        "homepage": homepage,
        "downloads": downloads,
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
        results.append({
            "name": crate.get("name", ""),
            "description": crate.get("description", ""),
            "latest_version": crate.get("newest_version", ""),
            "downloads": crate.get("downloads", 0),
        })

    return {
        "total": total,
        "results": results,
    }


def get_package(crate_name: str) -> dict:
    """
    获取 crates.io 包详情

    Args:
        crate_name: Crate 名称

    Returns:
        包信息字典
    """
    # 获取包基本信息（包含版本列表）
    url = f"{CRATES_API_URL}/crates/{crate_name}"
    data = fetch_json(url)

    crate = data.get("crate", {})
    name = crate.get("name", "")
    description = crate.get("description", "")

    # 获取版本列表
    versions_data = data.get("versions", [])
    versions = []
    for v in versions_data[:20]:  # 最多20个版本
        versions.append({
            "version": v.get("num", ""),
            "date": v.get("created_at", "")[:10] if v.get("created_at") else "",
        })

    # 获取最新版本信息
    latest_version = crate.get("newest_version", "") or crate.get("max_version", "")

    # 尝试从 versions 数组获取最新版本的许可证
    license = ""
    if versions_data:
        license = versions_data[0].get("license", "") if versions_data else ""

    # 下载 URL
    download_url = f"{CRATES_BASE_URL}/api/v1/crates/{name}"

    # 主页
    homepage = crate.get("homepage", "") or crate.get("documentation", "")

    # 总下载量
    downloads = crate.get("downloads", 0)

    return {
        "name": name,
        "description": description,
        "latest_version": latest_version,
        "versions": versions,
        "dependencies": {},  # 依赖需要单独 API 获取，此处简化
        "download_url": download_url,
        "license": license,
        "homepage": homepage,
        "downloads": downloads,
    }


def search_packages(keyword: str) -> dict:
    """
    搜索 crates.io 包

    Args:
        keyword: 搜索关键词

    Returns:
        搜索结果字典
    """
    url = f"{CRATES_API_URL}/crates?page=1&per_page=10&q={keyword}"
    data = fetch_json(url)
    return parse_search_results(data)


def main():
    """命令行入口"""
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python crates.py <crate-name>      # 查询包详情")
        print("  python crates.py --search <keyword>  # 搜索包")
        sys.exit(1)

    if sys.argv[1] == "--search":
        if len(sys.argv) < 3:
            print("Error: 请提供搜索关键词")
            sys.exit(1)
        keyword = sys.argv[2]
        result = search_packages(keyword)
    else:
        crate_name = sys.argv[1]
        result = get_package(crate_name)

    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
