#!/usr/bin/env python3
"""
PyPI 包查询脚本
支持包详情查询和关键词搜索
"""

import re
from functools import lru_cache
from urllib.parse import quote

from bs4 import BeautifulSoup

from base_ecosystem import BaseEcosystemAdapter
from utils import fetch_html, register_cache


# PyPI 基础 URL
PYPI_BASE_URL = "https://pypi.org"


# ============ 缓存（@lru_cache；resolve 模块级 fetch_html 以兼容 patch.object 测试）============
@lru_cache(maxsize=512)
def _fetch_cached(url: str) -> str:
    return fetch_html(url)


register_cache(_fetch_cached.cache_clear)


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
        match = re.search(r"(\d+\.\d+\.\d+)", version_text)
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
            ver_match = re.search(r"(\d+\.\d+\.\d+)", ver_text)
            if ver_match:
                date = ""
                if date_elem:
                    date_text = date_elem.get_text(strip=True)
                    date_match = re.search(r"(\d{4}-\d{2}-\d{2})", date_text)
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
            match = re.match(r"([a-zA-Z0-9_-]+)\s*(.+)?", line)
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
            req_match = re.findall(r"([a-zA-Z0-9_-]+)\s*[><=!~]+", code_text)
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
            results.append(
                {
                    "name": name,
                    "description": description,
                    "latest_version": version,
                }
            )

    # 尝试提取总数
    total = len(results)
    # PyPI 不显示总数，设为返回结果数
    return {
        "total": total,
        "results": results,
    }


class PyPiAdapter(BaseEcosystemAdapter):
    """PyPI 特异逻辑：HTML 抓取 + BeautifulSoup 解析。"""

    ECOSYSTEM_NAME = "pypi"

    def build_package_url(self, package_name: str) -> str:
        return f"{PYPI_BASE_URL}/project/{quote(package_name, safe='')}/"

    def build_search_url(self, keyword: str) -> str:
        return f"{PYPI_BASE_URL}/search/?q={quote(keyword, safe='')}"

    def parse_package_info(self, html_content: str, package_name: str) -> dict:
        return parse_package_info(html_content, package_name)

    def parse_search_results(self, html_content: str) -> dict:
        return parse_search_results(html_content)


_adapter = PyPiAdapter(fetcher=_fetch_cached)


# ============ 向后兼容模块级 API（测试与现有调用方依赖）============
def get_package(package_name: str) -> dict:
    """获取 PyPI 包详情（委托 adapter，第二次同 URL 走缓存）。"""
    return _adapter.get_package(package_name)


def search_packages(keyword: str) -> dict:
    """搜索 PyPI 包（委托 adapter）。"""
    return _adapter.search_packages(keyword)


def main():
    """命令行入口（委托 adapter）。"""
    _adapter.main()


if __name__ == "__main__":
    main()
