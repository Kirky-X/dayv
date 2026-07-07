#!/usr/bin/env python3
"""
Maven 依赖查询脚本
支持包详情查询和关键词搜索
输入格式: groupId:artifactId (如: org.springframework.boot:spring-boot)
"""

import re
from functools import lru_cache
from urllib.parse import quote

from bs4 import BeautifulSoup

from base_ecosystem import BaseEcosystemAdapter
from utils import fetch_html, register_cache


# Maven 基础 URL
MAVEN_BASE_URL = "https://mvnrepository.com"


# ============ 缓存（@lru_cache；resolve 模块级 fetch_html 以兼容 patch.object 测试）============
@lru_cache(maxsize=512)
def _fetch_cached(url: str) -> str:
    return fetch_html(url)


register_cache(_fetch_cached.cache_clear)


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
                    date_match = re.search(r"(\d{4}-\d{2}-\d{2})", date)
                    date = date_match.group(1) if date_match else ""
                    versions.append({"version": version, "date": date})

    # 提取最新版本
    latest_version = versions[0]["version"] if versions else ""

    # 提取许可证
    license = ""
    for elem in soup.select("a"):
        text = elem.get_text(strip=True)
        href = elem.get("href", "")
        if (
            "license" in text.lower() or "License" in text or "Apache" in text
        ) and href.startswith("http"):
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
        if (
            "Home Page" in text or "Github" in text or "GitHub" in text
        ) and href.startswith("http"):
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
        match = re.search(r"/artifact/([^/]+)/([^/]+)", href)
        if match:
            results.append(
                {
                    "name": f"{match.group(1)}:{match.group(2)}",
                    "description": description,
                    "latest_version": version,
                }
            )

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

                match = re.search(r"/artifact/([^/]+)/([^/]+)", href)
                if match:
                    results.append(
                        {
                            "name": f"{match.group(1)}:{match.group(2)}",
                            "description": description,
                            "latest_version": version,
                        }
                    )

    return {
        "total": len(results),
        "results": results,
    }


class MavenAdapter(BaseEcosystemAdapter):
    """Maven 特异逻辑：mvnrepository.com HTML 抓取 + groupId:artifactId 双段名。"""

    ECOSYSTEM_NAME = "maven"
    PACKAGE_USAGE_HINT = "<groupId>:<artifactId>"
    PACKAGE_FORMAT_HINT = "<groupId>:<artifactId>"
    PACKAGE_FORMAT_ERROR = "请使用 groupId:artifactId 格式"

    def validate_package_arg(self, arg: str) -> bool:
        return ":" in arg

    def split_package_arg(self, arg: str) -> tuple:
        group_id, artifact_id = arg.split(":", 1)
        return (group_id, artifact_id)

    def build_package_url(self, group_id: str, artifact_id: str) -> str:
        return (
            f"{MAVEN_BASE_URL}/artifact/{quote(group_id, safe='')}"
            f"/{quote(artifact_id, safe='')}"
        )

    def build_search_url(self, keyword: str) -> str:
        return f"{MAVEN_BASE_URL}/search?q={quote(keyword, safe='')}"

    def parse_package_info(
        self, html_content: str, group_id: str, artifact_id: str
    ) -> dict:
        return parse_package_info(html_content, group_id, artifact_id)

    def parse_search_results(self, html_content: str) -> dict:
        return parse_search_results(html_content)


_adapter = MavenAdapter(fetcher=_fetch_cached)


# ============ 向后兼容模块级 API ============
def get_package(group_id: str, artifact_id: str) -> dict:
    """获取 Maven 依赖详情（委托 adapter，第二次同 URL 走缓存）。"""
    return _adapter.get_package(group_id, artifact_id)


def search_packages(keyword: str) -> dict:
    """搜索 Maven 依赖（委托 adapter）。"""
    return _adapter.search_packages(keyword)


def main():
    """命令行入口（委托 adapter）。"""
    _adapter.main()


if __name__ == "__main__":
    main()
