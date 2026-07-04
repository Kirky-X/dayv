#!/usr/bin/env python3
"""
Impact Analyzer - 冲突影响范围分析
从冲突包出发反向追溯受影响的包，并找出从根到冲突包的依赖链

设计契约:
- 输入: deps_data schema + conflicts 列表（与 report_to_dict 输出 conflicts schema 一致）
- 输出: list of {
    conflict_package: str,
    required_versions: list[dict],
    affected_packages: list[str],         # 反向追溯到的所有依赖者（不含冲突包本身）
    dependency_chains: list[list[str]],   # 从根到冲突包的所有路径
  }
- BFS 反向遍历找受影响包
- DFS 找从根到冲突包的所有路径（带环检测）
"""

import logging
from collections import defaultdict, deque
from typing import Any, Dict, List, Set

logger = logging.getLogger(__name__)

# ============ 防爆炸常量 ============

MAX_AFFECTED_PACKAGES = 1000
MAX_CHAINS = 50
MAX_CHAIN_LENGTH = 50


# ============ 工具函数 ============


def _build_reverse_adjacency(deps_data: Dict[str, Any]) -> Dict[str, List[str]]:
    """构建反向邻接表: {target: [sources]}"""
    rev: Dict[str, List[str]] = defaultdict(list)
    for edge in deps_data.get("edges", []):
        src = edge.get("source", "")
        tgt = edge.get("target", "")
        if src and tgt:
            rev[tgt].append(src)
    return dict(rev)


def _build_forward_adjacency(deps_data: Dict[str, Any]) -> Dict[str, List[str]]:
    """构建正向邻接表: {source: [targets]}"""
    fwd: Dict[str, List[str]] = defaultdict(list)
    for edge in deps_data.get("edges", []):
        src = edge.get("source", "")
        tgt = edge.get("target", "")
        if src and tgt:
            fwd[src].append(tgt)
    return dict(fwd)


def _find_roots(deps_data: Dict[str, Any]) -> List[str]:
    """找根节点：is_root=True 优先，否则入度=0 的包，否则全部"""
    packages = deps_data.get("packages", [])
    roots = [p["name"] for p in packages if p.get("is_root")]
    if roots:
        return roots

    all_targets: Set[str] = set()
    for edge in deps_data.get("edges", []):
        tgt = edge.get("target", "")
        if tgt:
            all_targets.add(tgt)
    all_names = [p["name"] for p in packages if p.get("name")]
    no_incoming = [n for n in all_names if n not in all_targets]
    return no_incoming or all_names


def _bfs_reverse(rev_adj: Dict[str, List[str]], start: str) -> List[str]:
    """
    BFS 反向遍历：从 start 出发，找所有能到达 start 的包（不含 start 自己）

    Args:
        rev_adj: 反向邻接表
        start: 起点（冲突包名）

    Returns:
        受影响的包列表（按 BFS 顺序）
    """
    visited: Set[str] = {start}
    queue: deque = deque([start])
    result: List[str] = []

    while queue and len(result) < MAX_AFFECTED_PACKAGES:
        node = queue.popleft()
        for parent in rev_adj.get(node, []):
            if parent not in visited:
                visited.add(parent)
                result.append(parent)
                queue.append(parent)

    return result


def _find_all_paths(fwd_adj: Dict[str, List[str]],
                    roots: List[str],
                    target: str) -> List[List[str]]:
    """
    DFS 找所有从任一根到 target 的路径（带环检测）

    Args:
        fwd_adj: 正向邻接表
        roots: 根节点列表
        target: 目标包（冲突包）

    Returns:
        路径列表，每条路径是包名列表 [root, ..., target]
    """
    paths: List[List[str]] = []

    # stack: (node, path_so_far)
    stack: List[tuple] = [(root, [root]) for root in reversed(roots)]

    while stack and len(paths) < MAX_CHAINS:
        node, path = stack.pop()

        if len(path) > MAX_CHAIN_LENGTH:
            continue

        # 找到目标（且不是根自己）
        if node == target and len(path) > 1:
            paths.append(list(path))
            continue

        for child in fwd_adj.get(node, []):
            # 环检测：child 已在当前路径中则跳过
            if child in path:
                continue
            stack.append((child, path + [child]))

    return paths


# ============ 主函数 ============


def analyze_conflict_impact(deps_data: Dict[str, Any],
                            conflicts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    分析冲突影响范围

    Args:
        deps_data: {packages: [...], edges: [...]}
        conflicts: 冲突列表，每个元素 schema（与 report_to_dict 输出一致）:
            {package: str, required_by: [{package: str, constraint: str}],
             conflict_type: str, severity: str, suggestion: str}

    Returns:
        list of {
            conflict_package: str,
            required_versions: list[dict],     # [{package, constraint}]
            affected_packages: list[str],      # 反向追溯到的所有依赖者
            dependency_chains: list[list[str]] # 从根到冲突包的路径
        }
    """
    if not conflicts:
        return []

    rev_adj = _build_reverse_adjacency(deps_data)
    fwd_adj = _build_forward_adjacency(deps_data)
    roots = _find_roots(deps_data)

    results: List[Dict[str, Any]] = []
    for conflict in conflicts:
        pkg = conflict.get("package", "")
        if not pkg:
            logger.warning(f"跳过无 package 字段的冲突: {conflict}")
            continue

        required_by = conflict.get("required_by", [])
        required_versions = [
            {
                "package": rb.get("package", ""),
                "constraint": rb.get("constraint", ""),
            }
            for rb in required_by
        ]

        affected = _bfs_reverse(rev_adj, pkg)
        chains = _find_all_paths(fwd_adj, roots, pkg)

        results.append({
            "conflict_package": pkg,
            "required_versions": required_versions,
            "affected_packages": affected,
            "dependency_chains": chains,
        })

    return results


def format_impact_report(impacts: List[Dict[str, Any]]) -> str:
    """
    渲染冲突影响分析报告为可读文本

    Args:
        impacts: analyze_conflict_impact 的返回值

    Returns:
        文本报告字符串
    """
    if not impacts:
        return "未检测到冲突。"

    lines = ["冲突影响范围分析", "=" * 50]

    for i, impact in enumerate(impacts, 1):
        pkg = impact.get("conflict_package", "")
        lines.append(f"\n[{i}] 冲突包: {pkg}")

        required = impact.get("required_versions", [])
        if required:
            lines.append("  版本要求:")
            for r in required:
                rp = r.get("package", "")
                rc = r.get("constraint", "")
                lines.append(f"    - {rp}: {rc}")
        else:
            lines.append("  版本要求: 无")

        affected = impact.get("affected_packages", [])
        if affected:
            lines.append(f"  受影响包 ({len(affected)} 个):")
            for ap in affected:
                lines.append(f"    - {ap}")
        else:
            lines.append("  受影响包: 无")

        chains = impact.get("dependency_chains", [])
        if chains:
            lines.append(f"  依赖链 ({len(chains)} 条):")
            for chain in chains:
                lines.append(f"    - {' -> '.join(chain)}")
        else:
            lines.append("  依赖链: 无（冲突包与根之间无路径）")

    return "\n".join(lines)
