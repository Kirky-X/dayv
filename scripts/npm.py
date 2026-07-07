#!/usr/bin/env python3
"""
npm 包查询脚本
支持包详情查询和关键词搜索
"""

from functools import lru_cache

from base_ecosystem import BaseEcosystemAdapter
from utils import fetch_json, register_cache


# npm 基础 URL
NPM_REGISTRY_URL = "https://registry.npmjs.org"
NPM_SEARCH_URL = "https://www.npmjs.com"


# ============ 缓存（@lru_cache；resolve 模块级 fetch_json 以兼容 patch.object 测试）============
@lru_cache(maxsize=512)
def _fetch_cached(url: str) -> dict:
    return fetch_json(url)


register_cache(_fetch_cached.cache_clear)


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
        results.append(
            {
                "name": package.get("name", ""),
                "description": package.get("description", ""),
                "latest_version": package.get("version", ""),
            }
        )

    total = data.get("total", len(results))
    return {
        "total": total,
        "results": results,
    }


class NpmAdapter(BaseEcosystemAdapter):
    """npm 特异逻辑：registry JSON API。"""

    ECOSYSTEM_NAME = "npm"

    def build_package_url(self, package_name: str) -> str:
        return f"{NPM_REGISTRY_URL}/{package_name}"

    def build_search_url(self, keyword: str) -> str:
        # npm registry 搜索 API（免费，无需认证）
        return f"{NPM_REGISTRY_URL}/-/v1/search?text={keyword}&size=10"

    def parse_package_info(self, data: dict, *args) -> dict:
        return parse_package_info(data)

    def parse_search_results(self, data: dict) -> dict:
        return parse_search_results_json(data)


_adapter = NpmAdapter(fetcher=_fetch_cached)


# ============ 向后兼容模块级 API ============
def get_package(package_name: str) -> dict:
    """获取 npm 包详情（委托 adapter，第二次同 URL 走缓存）。"""
    return _adapter.get_package(package_name)


def search_packages(keyword: str) -> dict:
    """搜索 npm 包（委托 adapter）。"""
    return _adapter.search_packages(keyword)


def main():
    """命令行入口（委托 adapter）。"""
    _adapter.main()


if __name__ == "__main__":
    main()
