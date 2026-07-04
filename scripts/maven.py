#!/usr/bin/env python3
"""
Maven 依赖查询脚本
支持包详情查询和关键词搜索
输入格式: groupId:artifactId (如: org.springframework.boot:spring-boot)
"""

import json
import re
import sys
from typing import Optional
from urllib.parse import quote

from bs4 import BeautifulSoup

from utils import fetch_html


# Maven 基础 URL
MAVEN_BASE_URL = "https://mvnrepository.com"


def parse_package_info(html_content: str, group_id: str, artifact_id: str) -> dict:
    """
    解析 Maven 依赖详情页面

    Args:
        html_content: HTML 内容
        group_id: Group ID
        artifact_id: Artifact ID

    Returns:
        依赖信息字典
    """
    soup = BeautifulSoup(html_content, "html.parser")

    # 提取描述
    desc_elem = soup.select_one("h2")
    description = desc_elem.get_text(strip=True) if desc_elem else ""

    # 提取版本列表 - 从 grid 表格
    versions = []
    grid = soup.select_one(".grid")
    if grid:
        # 表格结构：Version | Vulnerabilities | Usages | Date
        rows = grid.select("tr")
        for row in rows[1:21]:  # 跳过表头，最多20个
            cols = row.select("td")
            if len(cols) >= 4:
                version_elem = cols[0].select_one("a")
                date_elem = cols[3]
                if version_elem:
                    version = version_elem.get_text(strip=True)
                    date = date_elem.get_text(strip=True)
                    # 格式化日期
                    date_match = re.search(r'(\d{4}-\d{2}-\d{2})', date)
                    date = date_match.group(1) if date_match else ""
                    versions.append({"version": version, "date": date})

    # 提取最新版本
    latest_version = versions[0]["version"] if versions else ""

    # 提取许可证
    license = ""
    for elem in soup.select("a"):
        text = elem.get_text(strip=True)
        href = elem.get("href", "")
        if ("license" in text.lower() or "License" in text or "Apache" in text) and href.startswith("http"):
            license = text
            break

    # 提取依赖
    dependencies = {}
    deps_section = soup.select_one("#dependencies, .dependencies, table.deps")
    if deps_section:
        for row in deps_section.select("tr"):
            cols = row.select("td")
            if len(cols) >= 2:
                dep_link = cols[0].select_one("a")
                dep_version = cols[1].select_one("a, span")
                if dep_link:
                    dep_name = dep_link.get_text(strip=True)
                    dep_ver = dep_version.get_text(strip=True) if dep_version else "*"
                    dependencies[dep_name] = dep_ver

    # 下载 URL
    download_url = f"{MAVEN_BASE_URL}/artifact/{group_id}/{artifact_id}"

    # 主页
    homepage = ""
    for link in soup.select("a"):
        href = link.get("href", "")
        text = link.get_text(strip=True)
        if ("Home Page" in text or "Github" in text or "GitHub" in text) and href.startswith("http"):
            homepage = href
            break

    return {
        "name": f"{group_id}:{artifact_id}",
        "description": description,
        "latest_version": latest_version,
        "versions": versions,
        "dependencies": dependencies,
        "download_url": download_url,
        "license": license,
        "homepage": homepage,
    }


def parse_search_results(html_content: str) -> dict:
    """
    解析 Maven 搜索结果页面

    Args:
        html_content: HTML 内容

    Returns:
        搜索结果字典
    """
    soup = BeautifulSoup(html_content, "html.parser")

    results = []

    # 尝试新的选择器结构 (.im-title 位于独立行)
    titles = soup.select(".im-title a")
    for title_elem in titles[:10]:
        href = title_elem.get("href", "")
        name = title_elem.get_text(strip=True)
        description = ""
        version = ""

        # 查找关联的版本和描述信息
        parent = title_elem.find_parent(["div", "td", "li"])
        if parent:
            # 版本信息可能在同一行或相邻元素
            version_elem = parent.select_one(".im-version, .v-btn, .version")
            if version_elem:
                version = version_elem.get_text(strip=True)

            # 描述可能在下一个元素
            desc_elem = parent.select_one(".im-description, .im-excerpt, .desc")
            if desc_elem:
                description = desc_elem.get_text(strip=True)

        # 提取 groupId:artifactId
        match = re.search(r'/artifact/([^/]+)/([^/]+)', href)
        if match:
            results.append({
                "name": f"{match.group(1)}:{match.group(2)}",
                "description": description,
                "latest_version": version,
            })

    # 备选：尝试旧的 .im-result-grid 选择器
    if not results:
        packages = soup.select(".im-result-grid")
        for pkg in packages[:10]:
            title_elem = pkg.select_one(".im-title a")
            desc_elem = pkg.select_one(".im-description")
            version_elem = pkg.select_one(".im-version")

            if title_elem:
                href = title_elem.get("href", "")
                name = title_elem.get_text(strip=True)
                description = desc_elem.get_text(strip=True) if desc_elem else ""
                version = version_elem.get_text(strip=True) if version_elem else ""

                match = re.search(r'/artifact/([^/]+)/([^/]+)', href)
                if match:
                    results.append({
                        "name": f"{match.group(1)}:{match.group(2)}",
                        "description": description,
                        "latest_version": version,
                    })

    return {
        "total": len(results),
        "results": results,
    }


def get_package(group_id: str, artifact_id: str) -> dict:
    """
    获取 Maven 依赖详情

    Args:
        group_id: Group ID
        artifact_id: Artifact ID

    Returns:
        依赖信息字典
    """
    url = f"{MAVEN_BASE_URL}/artifact/{quote(group_id, safe='')}/{quote(artifact_id, safe='')}"
    html = fetch_html(url)
    return parse_package_info(html, group_id, artifact_id)


def search_packages(keyword: str) -> dict:
    """
    搜索 Maven 依赖

    Args:
        keyword: 搜索关键词

    Returns:
        搜索结果字典
    """
    url = f"{MAVEN_BASE_URL}/search?q={quote(keyword, safe='')}"
    html = fetch_html(url)
    return parse_search_results(html)


def main():
    """命令行入口"""
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python maven.py <groupId>:<artifactId>  # 查询依赖详情")
        print("  python maven.py --search <keyword>       # 搜索依赖")
        sys.exit(1)

    if sys.argv[1] == "--search":
        if len(sys.argv) < 3:
            print("Error: 请提供搜索关键词")
            sys.exit(1)
        keyword = sys.argv[2]
        result = search_packages(keyword)
    else:
        # 解析 groupId:artifactId
        coord = sys.argv[1]
        if ":" not in coord:
            print("Error: 请使用 groupId:artifactId 格式")
            sys.exit(1)
        parts = coord.split(":", 1)
        group_id = parts[0]
        artifact_id = parts[1]
        result = get_package(group_id, artifact_id)

    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()
