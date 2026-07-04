#!/usr/bin/env python3
"""
Simulator - 升级影响模拟 (dry-run)
模拟升级某依赖到目标版本后的依赖树变化，输出风险等级 + 影响范围 + 回滚建议

设计契约:
- 输入: deps_data schema + package + target_version + ecosystem + 可选 fetcher
- 输出: {
    package: str,
    current_version: str,
    target_version: str,
    risk_level: "high" | "medium" | "low",
    added_dependencies: list[dict],     # [{name, constraint}]
    removed_dependencies: list[dict],   # [{name, constraint}]
    conflicts: list[dict],              # [{package, reason, existing_version, required_constraint}]
    rollback_suggestion: str,
  }
- 风险等级: major 升级=high, minor=medium, patch=low, 降级=high, 解析失败=high
- fetcher 可注入: 默认走 subprocess 调 ecosystem 脚本，测试时可传 mock
"""

import json
import logging
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import semver

from utils import check_version_constraint, clean_version_string

logger = logging.getLogger(__name__)


# ============ 回滚建议模板（按 ecosystem） ============

_ROLLBACK_TEMPLATES = {
    "pypi": "git checkout requirements.txt  # 或 pip install {pkg}=={old_ver}",
    "npm": "git checkout package.json && npm install  # 或 npm install {pkg}@{old_ver}",
    "maven": "git checkout pom.xml  # Maven 重新解析依赖",
    "crates": "git checkout Cargo.toml && cargo update  # 或 cargo update -p {pkg} --precise {old_ver}",
    "rubygems": "git checkout Gemfile && bundle install  # 或 bundle update {pkg}",
    "packagist": "git checkout composer.json && composer install  # 或 composer require {pkg}:{old_ver}",
    "nuget": "git checkout *.csproj && dotnet restore  # 或 dotnet add package {pkg} --version {old_ver}",
}

# ecosystem → 子脚本映射（与 dependency_analyzer.cmd_query 一致）
_ECOSYSTEM_SCRIPTS = {
    "pypi": "pypi.py",
    "npm": "npm.py",
    "maven": "maven.py",
    "crates": "crates.py",
    "rubygems": "rubygems.py",
    "packagist": "packagist.py",
    "nuget": "nuget.py",
}


# ============ 主函数 ============


def simulate_upgrade(deps_data: Dict[str, Any],
                     package: str,
                     target_version: str,
                     ecosystem: str = "pypi",
                     fetcher: Optional[Callable[[str, str, str], List[Dict[str, Any]]]] = None) -> Dict[str, Any]:
    """
    模拟升级依赖到目标版本的影响

    Args:
        deps_data: {packages: [...], edges: [...]}
        package: 待升级的包名
        target_version: 目标版本号
        ecosystem: 包生态系统（默认 pypi）
        fetcher: 可注入的依赖获取函数 (package, target_version, ecosystem) -> list[dict]
                 默认走 subprocess 调 ecosystem 脚本

    Returns:
        模拟结果 dict（见模块文档字符串 schema）
    """
    # 1. 找当前版本
    current_version = _find_current_version(deps_data, package)

    # 2. 风险等级判定
    risk_level = _compare_versions(current_version, target_version)

    # 3. 获取目标版本的依赖列表
    if fetcher is None:
        fetcher = _fetch_target_deps
    target_deps = fetcher(package, target_version, ecosystem)

    # 4. 从 deps_data 提取当前依赖
    current_deps = _extract_current_deps(deps_data, package)

    # 5. 比较 added / removed
    target_names = {d.get("name", "") for d in target_deps}
    current_names = {d.get("name", "") for d in current_deps}
    added = [d for d in target_deps if d.get("name", "") not in current_names]
    removed = [d for d in current_deps if d.get("name", "") not in target_names]

    # 6. 冲突检测：新增依赖的约束是否与现有依赖图冲突
    conflicts = _detect_conflicts(target_deps, deps_data)

    # 7. 回滚建议
    rollback = _rollback_suggestion(ecosystem, package, current_version)

    return {
        "package": package,
        "current_version": current_version,
        "target_version": target_version,
        "risk_level": risk_level,
        "added_dependencies": added,
        "removed_dependencies": removed,
        "conflicts": conflicts,
        "rollback_suggestion": rollback,
    }


# ============ 私有工具函数 ============


def _find_current_version(deps_data: Dict[str, Any], package: str) -> str:
    """从 deps_data 中查找包的当前版本，找不到返回 'unknown'"""
    for pkg in deps_data.get("packages", []):
        if pkg.get("name") == package:
            return pkg.get("version", "unknown")
    return "unknown"


def _compare_versions(current: str, target: str) -> str:
    """
    风险等级判定

    Args:
        current: 当前版本号
        target: 目标版本号

    Returns:
        "high" | "medium" | "low"
        - 降级 = high
        - major 升级 = high
        - minor 升级 = medium
        - patch 升级或相同 = low
        - 版本解析失败 = high（保守处理，不静默假设低风险）
    """
    try:
        cur = semver.Version.parse(clean_version_string(current))
        tgt = semver.Version.parse(clean_version_string(target))

        # 降级 = high
        if tgt < cur:
            return "high"
        # major 升级 = high
        if tgt.major > cur.major:
            return "high"
        # minor 升级 = medium
        if tgt.minor > cur.minor:
            return "medium"
        # patch 升级或相同 = low
        return "low"
    except (ValueError, TypeError) as e:
        logger.warning(
            f"版本比较失败 current={current} target={target}: {e}，按 high 风险处理"
        )
        return "high"


def _extract_current_deps(deps_data: Dict[str, Any], package: str) -> List[Dict[str, Any]]:
    """
    从 deps_data 提取 package 的直接依赖列表

    Returns:
        [{name, constraint}, ...]
    """
    deps: List[Dict[str, Any]] = []
    for edge in deps_data.get("edges", []):
        if edge.get("source") == package:
            deps.append({
                "name": edge.get("target", ""),
                "constraint": edge.get("constraint", "*"),
            })
    return deps


def _fetch_target_deps(package: str, target_version: str, ecosystem: str) -> List[Dict[str, Any]]:
    """
    调用 ecosystem 子脚本获取目标版本的依赖列表

    Args:
        package: 包名
        target_version: 目标版本（用于日志，实际查询取最新版依赖）
        ecosystem: 生态系统

    Returns:
        [{name, constraint}, ...]
        查询失败时返回空列表（显式记录日志，不静默）
    """
    script_name = _ECOSYSTEM_SCRIPTS.get(ecosystem)
    if not script_name:
        logger.error(f"不支持的生态系统: {ecosystem}")
        return []

    script_path = Path(__file__).parent / script_name
    if not script_path.exists():
        logger.error(f"ecosystem 脚本不存在: {script_path}")
        return []

    try:
        result = subprocess.run(
            [sys.executable, str(script_path), package],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode != 0:
            logger.warning(
                f"查询 {package}@{target_version} 失败 (exit={result.returncode}): "
                f"{result.stderr.strip()}"
            )
            return []

        pkg_info = json.loads(result.stdout)
        raw_deps = pkg_info.get("dependencies", {})

        # 统一为 list[dict] 格式
        if isinstance(raw_deps, dict):
            return [{"name": k, "constraint": v} for k, v in raw_deps.items()]
        if isinstance(raw_deps, list):
            return raw_deps
        return []
    except subprocess.TimeoutExpired:
        logger.warning(f"查询 {package} 超时（60s）")
        return []
    except json.JSONDecodeError as e:
        logger.warning(f"解析 {package} 响应失败: {e}")
        return []
    except Exception as e:
        logger.warning(f"获取 {package}@{target_version} 依赖失败: {e}")
        return []


def _detect_conflicts(new_deps: List[Dict[str, Any]],
                      deps_data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    检测新增依赖的约束是否与现有依赖图中的版本冲突

    Args:
        new_deps: 目标版本的依赖列表 [{name, constraint}]
        deps_data: 现有依赖图

    Returns:
        冲突列表 [{package, reason, existing_version, required_constraint}]
    """
    conflicts: List[Dict[str, Any]] = []

    # 现有依赖图中的包版本: {name: [version, ...]}
    existing_versions: Dict[str, List[str]] = {}
    for pkg in deps_data.get("packages", []):
        name = pkg.get("name", "")
        ver = pkg.get("version", "")
        if name and ver:
            existing_versions.setdefault(name, []).append(ver)

    for dep in new_deps:
        name = dep.get("name", "")
        constraint = dep.get("constraint", "*")
        if not name or name not in existing_versions:
            continue

        # 检查现有版本是否满足新约束
        for existing_ver in existing_versions[name]:
            if not check_version_constraint(existing_ver, constraint):
                conflicts.append({
                    "package": name,
                    "reason": (
                        f"目标版本需要 {constraint}，"
                        f"现有版本 {existing_ver} 不满足"
                    ),
                    "existing_version": existing_ver,
                    "required_constraint": constraint,
                })

    return conflicts


def _rollback_suggestion(ecosystem: str, package: str, old_version: str) -> str:
    """
    生成回滚建议

    Args:
        ecosystem: 生态系统
        package: 包名
        old_version: 原版本号

    Returns:
        回滚建议字符串
    """
    template = _ROLLBACK_TEMPLATES.get(
        ecosystem, "git checkout 依赖配置文件"
    )
    return template.format(pkg=package, old_ver=old_version)


# ============ 渲染输出 ============


def format_simulation_report(result: Dict[str, Any]) -> str:
    """
    渲染模拟结果为可读文本

    Args:
        result: simulate_upgrade 的返回值

    Returns:
        文本报告字符串
    """
    lines = [
        "升级影响模拟",
        "=" * 50,
        f"包名: {result.get('package', '')}",
        f"当前版本: {result.get('current_version', '')}",
        f"目标版本: {result.get('target_version', '')}",
        f"风险等级: {result.get('risk_level', '').upper()}",
    ]

    added = result.get("added_dependencies", [])
    removed = result.get("removed_dependencies", [])
    conflicts = result.get("conflicts", [])

    lines.append(f"\n新增依赖 ({len(added)} 个):")
    if added:
        for d in added:
            lines.append(f"  + {d.get('name', '')}: {d.get('constraint', '*')}")
    else:
        lines.append("  (无)")

    lines.append(f"\n移除依赖 ({len(removed)} 个):")
    if removed:
        for d in removed:
            lines.append(f"  - {d.get('name', '')}: {d.get('constraint', '*')}")
    else:
        lines.append("  (无)")

    lines.append(f"\n冲突 ({len(conflicts)} 个):")
    if conflicts:
        for c in conflicts:
            lines.append(f"  ! {c.get('package', '')}: {c.get('reason', '')}")
    else:
        lines.append("  (无)")

    lines.append(f"\n回滚建议: {result.get('rollback_suggestion', '')}")
    return "\n".join(lines)
