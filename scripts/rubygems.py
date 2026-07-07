#!/usr/bin/env python3
"""
RubyGems (Ruby) 包查询脚本
支持包详情查询和关键词搜索
API 文档: https://guides.rubygems.org/rubygems-org-api/
"""

import logging
from functools import lru_cache
from urllib.parse import quote

from base_ecosystem import BaseEcosystemAdapter
from utils import fetch_json, register_cache


# 配置日志
logger = logging.getLogger(__name__)

# RubyGems API 基础 URL
RUBYGEMS_API_URL = "https://rubygems.org/api/v1"


# ============ 缓存（@lru_cache；resolve 模块级 fetch_json 以兼容 patch.object 测试）============
@lru_cache(maxsize=512)
def _fetch_cached(url: str) -> dict:
    return fetch_json(url)


register_cache(_fetch_cached.cache_clear)


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
        results.append(
            {
                "name": gem.get("name", ""),
                "description": gem.get("info", ""),
                "latest_version": gem.get("version", ""),
            }
        )

    return {
        "total": len(results),
        "results": results,
    }


class RubyGemsAdapter(BaseEcosystemAdapter):
    """RubyGems 特异逻辑：JSON API + 主端点不返回 deps，需额外取 deps 端点合并。"""

    ECOSYSTEM_NAME = "rubygems"

    def build_package_url(self, gem_name: str) -> str:
        return f"{RUBYGEMS_API_URL}/gems/{quote(gem_name, safe='')}.json"

    def build_search_url(self, keyword: str) -> str:
        return f"{RUBYGEMS_API_URL}/search.json?query={quote(keyword)}"

    def parse_package_info(self, data: dict, *args) -> dict:
        return parse_package_info(data)

    def parse_search_results(self, data: list) -> dict:
        return parse_search_results(data)

    def post_fetch(self, gem_name: str, data) -> dict:
        """额外请求 dependencies 端点合并依赖（主端点不返回）。

        RubyGems dependencies API 返回 {"dependencies": [...], "development": [...]}；
        parse_package_info 期望 data["dependencies"] 是
        {"runtime": [...], "development": [...]}。
        """
        deps_url = (
            f"{RUBYGEMS_API_URL}/gems/{quote(gem_name, safe='')}/dependencies.json"
        )
        try:
            deps_data = self._fetcher(deps_url)
            if isinstance(deps_data, dict):
                data["dependencies"] = {
                    "runtime": deps_data.get("dependencies", []),
                    "development": deps_data.get("development", []),
                }
        except Exception as e:
            logger.warning(f"获取 {gem_name} dependencies 失败: {e}")
        return data


_adapter = RubyGemsAdapter(fetcher=_fetch_cached)


# ============ 向后兼容模块级 API ============
def get_package(gem_name: str) -> dict:
    """获取 RubyGems 包详情（委托 adapter；主端点 + deps 端点各自走缓存）。"""
    return _adapter.get_package(gem_name)


def search_packages(keyword: str) -> dict:
    """搜索 RubyGems 包（委托 adapter）。"""
    return _adapter.search_packages(keyword)


def main():
    """命令行入口（委托 adapter）。"""
    _adapter.main()


if __name__ == "__main__":
    main()
