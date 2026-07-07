#!/usr/bin/env python3
"""
Readme Generator - 项目依赖 README 生成器
从依赖列表生成"依赖说明"章节（markdown），可插入项目 README

设计契约:
- 输入: deps_data schema（与 cmd_report 一致: {packages, edges}）
- 输出: markdown 字符串，含 ## 依赖说明 章节
- 按 ecosystem 分组（PyPI / npm / Maven ...），每组一个表格
- 表格列: 包名 | 版本 | 用途 | 许可证
- fetcher 注入: 测试时传 mock，CLI 调用时传 EcosystemFetcher（subprocess 调 ecosystem 脚本）
- 未传 fetcher: 不查 registry，用途/许可证列显示占位符 "-"
- 根包（is_root=True）不出现在依赖表格中
"""

import json
import logging
import subprocess
import sys
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ============ 常量 ============

PLACEHOLDER = "-"

# Ecosystem → (中文名, 脚本名)
# 顺序固定（PyPI 永远在 npm 前，便于人类阅读）
ECOSYSTEM_INFO: Dict[str, tuple] = {
    "pypi": ("PyPI", "pypi.py"),
    "npm": ("npm", "npm.py"),
    "maven": ("Maven", "maven.py"),
    "crates": ("crates", "crates.py"),
    "rubygems": ("RubyGems", "rubygems.py"),
    "packagist": ("Packagist", "packagist.py"),
    "nuget": ("NuGet", "nuget.py"),
}

# 默认 ecosystem 输出顺序（未在列表中的排最后）
ECOSYSTEM_ORDER = list(ECOSYSTEM_INFO.keys())

# subprocess 查询超时（秒）
FETCH_TIMEOUT = 15


# ============ EcosystemFetcher ============


class EcosystemFetcher:
    """通过 subprocess 调用 ecosystem 脚本获取包信息（CLI 用）"""

    # 并发上限：保留 registries 限流（过高会触发 429）。
    # 单请求限流仍由各 ecosystem 脚本内的 RequestClient 随机延迟负责。
    MAX_WORKERS = 4

    def __init__(self):
        self._cache: Dict[tuple, dict] = {}
        # 全量信息缓存（get_package / get_package_many 返回含 dependencies 的完整 dict）
        self._cache_full: Dict[tuple, dict] = {}

    def fetch(self, package_name: str, ecosystem: str) -> dict:
        """
        获取包信息

        Args:
            package_name: 包名
            ecosystem: 生态系统（pypi/npm/maven/...）

        Returns:
            {"description": str, "license": str} 或空 dict（查询失败）
        """
        cache_key = (package_name, ecosystem)
        if cache_key in self._cache:
            return self._cache[cache_key]

        info = self._fetch_uncached(package_name, ecosystem)
        self._cache[cache_key] = info
        return info

    def fetch_many(
        self, items: Iterable[Tuple[str, str]]
    ) -> Dict[Tuple[str, str], dict]:
        """
        批量并发查询（ThreadPoolExecutor + 缓存命中短路）。

        保留限流：MAX_WORKERS 上限 + 各 ecosystem 脚本内 RequestClient 的随机延迟。
        失败回退与 fetch() 一致（空 dict，不抛异常）。

        Args:
            items: 可迭代的 (package_name, ecosystem) 序列

        Returns:
            {(name, ecosystem): info_dict}，未查询到/失败的为 {}
        """
        keys = list(items)
        results: Dict[Tuple[str, str], dict] = {}
        to_fetch: List[Tuple[str, str]] = []
        for key in keys:
            if key in self._cache:
                results[key] = self._cache[key]
            else:
                to_fetch.append(key)

        if to_fetch:
            with ThreadPoolExecutor(max_workers=self.MAX_WORKERS) as ex:
                futures = {
                    ex.submit(self._fetch_uncached, name, eco): (name, eco)
                    for (name, eco) in to_fetch
                }
                for fut in as_completed(futures):
                    name, eco = futures[fut]
                    try:
                        info = fut.result()
                    except Exception as e:  # 双保险：_fetch_uncached 已吞异常
                        logger.debug(f"fetch_many 查询 {name}/{eco} 异常: {e}")
                        info = {}
                    self._cache[(name, eco)] = info
                    results[(name, eco)] = info
        return results

    def _fetch_uncached(self, package_name: str, ecosystem: str) -> dict:
        info_tuple = ECOSYSTEM_INFO.get(ecosystem)
        if not info_tuple:
            logger.debug(f"未知 ecosystem: {ecosystem}")
            return {}

        script_name = info_tuple[1]
        script_path = Path(__file__).parent / script_name
        if not script_path.exists():
            logger.debug(f"脚本不存在: {script_path}")
            return {}

        try:
            result = subprocess.run(
                [sys.executable, str(script_path), package_name],
                capture_output=True,
                text=True,
                timeout=FETCH_TIMEOUT,
            )
            if result.returncode != 0:
                logger.debug(
                    f"查询 {ecosystem}/{package_name} 失败: "
                    f"{result.stderr[:200] if result.stderr else 'no stderr'}"
                )
                return {}
            data = json.loads(result.stdout)
            return {
                "description": data.get("description", ""),
                "license": data.get("license", ""),
            }
        except subprocess.TimeoutExpired:
            logger.debug(f"查询 {ecosystem}/{package_name} 超时")
            return {}
        except json.JSONDecodeError as e:
            logger.debug(f"解析 {ecosystem}/{package_name} 响应失败: {e}")
            return {}
        except Exception as e:
            logger.debug(f"查询 {ecosystem}/{package_name} 异常: {e}")
            return {}

    # ============ 全量包信息（含 dependencies）============
    # 供 dependency_optimizer.find_redundant deep 模式等需要依赖图的场景使用。
    # 与 fetch / fetch_many（仅返回 description/license）并存，避免影响 readme 路径契约。

    def get_package(self, package_name: str, ecosystem: str) -> dict:
        """
        获取包的完整信息（含 dependencies），带缓存。

        Args:
            package_name: 包名
            ecosystem: 生态系统（pypi/npm/maven/...）

        Returns:
            完整 schema dict（{name, description, latest_version, versions,
            dependencies, download_url, license, homepage}）；失败返回 {}
        """
        cache_key = (package_name, ecosystem)
        if cache_key in self._cache_full:
            return self._cache_full[cache_key]
        info = self._fetch_full_uncached(package_name, ecosystem)
        self._cache_full[cache_key] = info
        return info

    def get_package_many(
        self, items: Iterable[Tuple[str, str]]
    ) -> Dict[Tuple[str, str], dict]:
        """
        批量并发全量查询（ThreadPoolExecutor + 缓存命中短路）。

        registry 包查询并发入口：MAX_WORKERS=4 上限保留 registry 限流，单请求限流
        仍由各 ecosystem 子脚本内 RequestClient 随机延迟负责。

        Args:
            items: 可迭代的 (package_name, ecosystem) 序列

        Returns:
            {(name, ecosystem): full_dict}，未查询到/失败的为 {}
        """
        keys = list(items)
        results: Dict[Tuple[str, str], dict] = {}
        to_fetch: List[Tuple[str, str]] = []
        for key in keys:
            if key in self._cache_full:
                results[key] = self._cache_full[key]
            else:
                to_fetch.append(key)

        if to_fetch:
            with ThreadPoolExecutor(max_workers=self.MAX_WORKERS) as ex:
                futures = {
                    ex.submit(self._fetch_full_uncached, name, eco): (name, eco)
                    for (name, eco) in to_fetch
                }
                for fut in as_completed(futures):
                    name, eco = futures[fut]
                    try:
                        info = fut.result()
                    except Exception as e:  # 双保险：_fetch_full_uncached 已吞异常
                        logger.debug(f"get_package_many 查询 {name}/{eco} 异常: {e}")
                        info = {}
                    self._cache_full[(name, eco)] = info
                    results[(name, eco)] = info
        return results

    def _fetch_full_uncached(self, package_name: str, ecosystem: str) -> dict:
        """subprocess 调 ecosystem 子脚本，返回完整 parse dict（含 dependencies）。"""
        info_tuple = ECOSYSTEM_INFO.get(ecosystem)
        if not info_tuple:
            logger.debug(f"未知 ecosystem: {ecosystem}")
            return {}

        script_name = info_tuple[1]
        script_path = Path(__file__).parent / script_name
        if not script_path.exists():
            logger.debug(f"脚本不存在: {script_path}")
            return {}

        try:
            result = subprocess.run(
                [sys.executable, str(script_path), package_name],
                capture_output=True,
                text=True,
                timeout=FETCH_TIMEOUT,
            )
            if result.returncode != 0:
                logger.debug(
                    f"全量查询 {ecosystem}/{package_name} 失败: "
                    f"{result.stderr[:200] if result.stderr else 'no stderr'}"
                )
                return {}
            return json.loads(result.stdout)
        except subprocess.TimeoutExpired:
            logger.debug(f"全量查询 {ecosystem}/{package_name} 超时")
            return {}
        except json.JSONDecodeError as e:
            logger.debug(f"解析 {ecosystem}/{package_name} 响应失败: {e}")
            return {}
        except Exception as e:
            logger.debug(f"全量查询 {ecosystem}/{package_name} 异常: {e}")
            return {}


# ============ 主函数 ============


def generate_dependency_readme(
    deps_data: Dict[str, Any], fetcher: Optional[object] = None
) -> str:
    """
    从依赖数据生成 markdown 依赖说明章节

    Args:
        deps_data: {packages: [{name, version, ecosystem, is_root?}], edges: [...]}
        fetcher: 可选，必须有 fetch(name, ecosystem) -> dict 方法。
                 None 时不查 registry，用途/许可证列显示占位符。

    Returns:
        markdown 字符串
    """
    packages = deps_data.get("packages", [])

    # 过滤根包（项目本身不是依赖）
    dep_packages = [p for p in packages if not p.get("is_root")]

    if not dep_packages:
        return "## 依赖说明\n\n暂无依赖。\n"

    # 按 ecosystem 分组
    by_ecosystem: Dict[str, List[dict]] = defaultdict(list)
    for pkg in dep_packages:
        eco = pkg.get("ecosystem", "unknown")
        by_ecosystem[eco].append(pkg)

    lines: List[str] = ["## 依赖说明", ""]

    # 按固定顺序输出已知 ecosystem，未知 ecosystem 排最后
    known = [e for e in ECOSYSTEM_ORDER if e in by_ecosystem]
    unknown = [e for e in by_ecosystem if e not in ECOSYSTEM_INFO]
    ordered = known + sorted(unknown)

    # 批量并发预取（EcosystemFetcher.fetch_many 走 ThreadPoolExecutor）。
    # 测试用的 mock fetcher 通常只实现 .fetch，无 fetch_many → 回退到逐个查询。
    batch_infos: Dict[Tuple[str, str], dict] = {}
    if fetcher is not None and hasattr(fetcher, "fetch_many"):
        all_items = [
            (pkg.get("name", ""), pkg.get("ecosystem", "unknown"))
            for pkg in dep_packages
        ]
        try:
            batch_infos = fetcher.fetch_many(all_items)
        except Exception as e:
            logger.debug(f"fetch_many 批量查询失败，回退逐个查询: {e}")
            batch_infos = {}

    for eco in ordered:
        pkgs = by_ecosystem[eco]
        eco_cn = ECOSYSTEM_INFO.get(eco, (eco, None))[0]
        lines.append(f"### {eco_cn} ({len(pkgs)} 个)")
        lines.append("")
        lines.append("| 包名 | 版本 | 用途 | 许可证 |")
        lines.append("|------|------|------|--------|")

        for pkg in pkgs:
            name = pkg.get("name", "")
            version = pkg.get("version", "")

            description = PLACEHOLDER
            license_info = PLACEHOLDER

            if fetcher is not None:
                try:
                    if batch_infos:
                        info = batch_infos.get((name, eco), {})
                    else:
                        info = fetcher.fetch(name, eco)  # mock fetcher 回退路径
                    if info.get("description"):
                        description = info["description"]
                    if info.get("license"):
                        license_info = info["license"]
                except Exception as e:
                    logger.debug(f"fetcher 查询 {name} 失败: {e}")

            # 转义 markdown 表格中的 | 字符
            description = description.replace("|", "\\|")
            license_info = license_info.replace("|", "\\|")

            lines.append(f"| {name} | {version} | {description} | {license_info} |")

        lines.append("")

    return "\n".join(lines)
