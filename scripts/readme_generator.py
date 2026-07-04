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
from pathlib import Path
from typing import Any, Dict, List, Optional

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

    def __init__(self):
        self._cache: Dict[tuple, dict] = {}

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
                capture_output=True, text=True, timeout=FETCH_TIMEOUT,
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


# ============ 主函数 ============


def generate_dependency_readme(deps_data: Dict[str, Any],
                                fetcher: Optional[object] = None) -> str:
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
                    info = fetcher.fetch(name, eco)
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
