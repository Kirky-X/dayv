#!/usr/bin/env python3
"""
PyPI 包查询脚本
支持包详情查询和关键词搜索
"""

import json
import re
import sys
from typing import Optional
from urllib.parse import quote

from bs4 import BeautifulSoup

from utils import fetch_html


# PyPI 基础 URL
PYPI_BASE_URL = "https://pypi.org"


def parse_package_info(html_content: str, package_name: str) -> dict:
    """
    解析 PyPI 包详情页面

    Args:
        html_content: HTML 内容
        package_name: 包名称

    Returns:
        包信息字典
    """
    soup = BeautifulSoup(html_content, "html.parser")

    # 提取描述
    description_elem = soup.select_one("meta[name='description']")
    description = description_elem.get("content", "") if description_elem else ""

    # 提取最新版本 - 从页面头部
    version = ""
    version_elem = soup.select_one("h1.package-header__name")
    if version_elem:
        version_text = version_elem.get_text(strip=True)
        match = re.search(r'(\d+\.\d+\.\d+)', version_text)
        if match:
            version = match.group(1)

    # 提取许可证
    license = ""
    for elem in soup.select("a"):
        text = elem.get_text(strip=True)
        href = elem.get("href", "")
        if ("license" in text.lower() or "License" in text) and href.startswith("http"):
            license = text
            break

    # 提取项目主页
    homepage = ""
    links_section = soup.select_one("#project-links, .vertical-tabs__tabs")
    if links_section:
        for link in links_section.select("a"):
            text = link.get_text(strip=True)
            href = link.get("href", "")
            if ("Homepage" in text or "Repository" in text) and href.startswith("http"):
                homepage = href
                break

    # 提取版本历史 - 从 release 表格
    versions = []
    version_rows = soup.select(".release, .vertical-tabs__tab")
    for row in version_rows:
        ver_elem = row.select_one(".release__version, code")
        date_elem = row.select_one("time, .grey")
        if ver_elem:
            ver_text = ver_elem.get_text(strip=True)
            ver_match = re.search(r'(\d+\.\d+\.\d+)', ver_text)
            if ver_match:
                date = ""
                if date_elem:
                    date_text = date_elem.get_text(strip=True)
                    date_match = re.search(r'(\d{4}-\d{2}-\d{2})', date_text)
                    if date_match:
                        date = date_match.group(1)
                versions.append({"version": ver_match.group(1), "date": date})
    versions = versions[:20]

    # 提取依赖 - 从 JSON-LD 或安装部分
    dependencies = {}
    deps_section = soup.select_one("#dependencies, #requires")
    if deps_section:
        dep_text = deps_section.get_text(strip=True)
        for line in dep_text.split("\n"):
            line = line.strip()
            if not line or line.lower().startswith("requires"):
                continue
            # 匹配 "package (version)" 或 "package>=version"
            match = re.match(r'([a-zA-Z0-9_-]+)\s*(.+)?', line)
            if match:
                dep_name = match.group(1)
                dep_ver = match.group(2).strip().strip("()") if match.group(2) else "*"
                dependencies[dep_name] = dep_ver

    # 备用：尝试从安装代码块提取依赖
    if not dependencies:
        install_code = soup.select_one("pre, code")
        if install_code:
            code_text = install_code.get_text()
            # 查找 requirements 格式
            req_match = re.findall(r'([a-zA-Z0-9_-]+)\s*[><=!~]+', code_text)
            for req in req_match:
                if req and req not in dependencies:
                    dependencies[req] = "*"

    # 下载 URL
    download_url = f"{PYPI_BASE_URL}/project/{package_name}/#files"

    return {
        "name": package_name,
        "description": description,
        "latest_version": version,
        "versions": versions,
        "dependencies": dependencies,
        "download_url": download_url,
        "license": license,
        "homepage": homepage,
    }


def parse_search_results(html_content: str) -> dict:
    """
    解析 PyPI 搜索结果页面

    Args:
        html_content: HTML 内容

    Returns:
        搜索结果字典
    """
    soup = BeautifulSoup(html_content, "html.parser")

    results = []
    packages = soup.select(".package-snippet")
    for pkg in packages[:10]:  # 最多10个结果
        name_elem = pkg.select_one(".package-snippet__name")
        desc_elem = pkg.select_one(".package-snippet__description")
        version_elem = pkg.select_one(".package-snippet__version")

        name = name_elem.get_text(strip=True) if name_elem else ""
        description = desc_elem.get_text(strip=True) if desc_elem else ""
        version = version_elem.get_text(strip=True) if version_elem else ""

        if name:
            results.append({
                "name": name,
                "description": description,
                "latest_version": version,
            })

    # 尝试提取总数
    total = len(results)
    # PyPI 不显示总数，设为返回结果数
    return {
        "total": total,
        "results": results,
    }


def get_package(package_name: str) -> dict:
    """
    获取 PyPI 包详情

    Args:
        package_name: 包名称

    Returns:
        包信息字典
    """
    url = f"{PYPI_BASE_URL}/project/{quote(package_name, safe='')}/"
    html = fetch_html(url)
    return parse_package_info(html, package_name)


def search_packages(keyword: str) -> dict:
    """
    搜索 PyPI 包

    Args:
        keyword: 搜索关键词

    Returns:
        搜索结果字典
    """
    url = f"{PYPI_BASE_URL}/search/?q={quote(keyword, safe='')}"
    html = fetch_html(url)
    return parse_search_results(html)


def main():
    """命令行入口"""
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python pypi.py <package-name>       # 查询包详情")
        print("  python pypi.py --search <keyword>   # 搜索包")
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
