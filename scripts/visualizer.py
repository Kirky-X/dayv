#!/usr/bin/env python3
"""
Visualizer - 依赖树可视化
渲染 Mermaid flowchart 格式的依赖树

设计契约:
- 输入: deps_data schema（与 cmd_report 一致: {packages, edges}）
- 输出: ```mermaid ... ``` 包裹的代码块字符串
- 节点 ID: P0/P1/...（避免重名 + Mermaid 非法字符）
- 节点 label: "name@version"
- 边: A --> B 表示 A 依赖 B
- depth=N: 从根出发 N 层依赖（root 本身不计入 depth）
- 循环依赖: 标注 %% CIRCULAR DETECTED 并停止该分支
"""

import logging
import re
from collections import defaultdict
from typing import Any, Dict, List, Set, Tuple

logger = logging.getLogger(__name__)

# ============ 常量 ============

DEFAULT_DEPTH = 3
NODE_ID_PREFIX = "P"
CIRCULAR_MARKER = "%% CIRCULAR DETECTED"


# ============ 工具函数 ============


def _sanitize_node_id(name: str) -> str:
    """
    将包名转为合法的 Mermaid 节点 ID 候选

    Mermaid 节点 ID 不允许含 @ / . 空格 等特殊字符。
    本函数保留给 debug 用；实际渲染用 P{index} 序号分配。
    """
    safe = re.sub(r'[^a-zA-Z0-9_]', '_', name)
    if safe and safe[0].isdigit():
        safe = "_" + safe
    return safe


def _build_adjacency(deps_data: Dict[str, Any]) -> Dict[str, List[str]]:
    """构建正向邻接表: {source: [targets]}"""
    adj: Dict[str, List[str]] = defaultdict(list)
    for edge in deps_data.get("edges", []):
        src = edge.get("source", "")
        tgt = edge.get("target", "")
        if src and tgt:
            adj[src].append(tgt)
    return dict(adj)


def _find_roots(packages: List[Dict[str, Any]],
                adj: Dict[str, List[str]]) -> List[str]:
    """
    找根节点（优先级）:
    1. is_root=True 的包
    2. 入度为 0 的包
    3. 全部包兜底
    """
    roots = [p["name"] for p in packages if p.get("is_root")]
    if roots:
        return roots

    all_targets: Set[str] = set()
    for targets in adj.values():
        all_targets.update(targets)
    all_names = [p["name"] for p in packages if p.get("name")]
    no_incoming = [n for n in all_names if n not in all_targets]
    if no_incoming:
        return no_incoming

    return all_names


# ============ 主函数 ============


def render_mermaid_tree(deps_data: Dict[str, Any],
                        depth: int = DEFAULT_DEPTH) -> str:
    """
    渲染 Mermaid flowchart 依赖树

    Args:
        deps_data: 依赖数据 schema:
            {packages: [{name, version, ecosystem?, is_root?}], edges: [{source, target, constraint?}]}
        depth: 渲染深度（从根出发的依赖层数），默认 3

    Returns:
        ```mermaid ... ``` 包裹的代码块字符串
    """
    packages = deps_data.get("packages", [])
    edges = deps_data.get("edges", [])

    # 包名 -> 版本映射
    versions: Dict[str, str] = {}
    for pkg in packages:
        name = pkg.get("name", "")
        if name:
            versions[name] = pkg.get("version", "")

    # 邻接表 + 根节点
    adj = _build_adjacency(deps_data)
    roots = _find_roots(packages, adj)

    # 节点 ID 分配（P0, P1, ... 顺序分配，避免重名 + 非法字符）
    node_ids: Dict[str, str] = {}
    next_id = [0]

    def get_id(name: str) -> str:
        if name not in node_ids:
            node_ids[name] = f"{NODE_ID_PREFIX}{next_id[0]}"
            next_id[0] += 1
        return node_ids[name]

    # DFS 遍历（迭代式，避免栈过深）
    visited_nodes: List[str] = []          # 保留首次访问顺序
    visited_set: Set[str] = set()
    rendered_edges: List[Tuple[str, str]] = []
    rendered_edge_set: Set[Tuple[str, str]] = set()
    circular_notes: List[str] = []

    # stack 元素: (node, current_depth, path_set)
    # current_depth: root=0, 直接依赖=1, 二级依赖=2 ...
    # path_set: 当前 DFS 路径上的节点集合（用于环检测）
    stack: List[Tuple[str, int, frozenset]] = [
        (root, 0, frozenset()) for root in reversed(roots)
    ]

    while stack:
        node, cur_depth, path = stack.pop()

        # 节点定义只输出一次
        if node not in visited_set:
            visited_set.add(node)
            visited_nodes.append(node)
            get_id(node)  # 预分配 ID

        # 达到深度上限，不再展开
        if cur_depth >= depth:
            continue

        # 遍历依赖
        for child in adj.get(node, []):
            edge_key = (node, child)
            if edge_key not in rendered_edge_set:
                rendered_edge_set.add(edge_key)
                rendered_edges.append(edge_key)

            # 环检测：child 在当前 path 中或 child == node（自环）
            if child in path or child == node:
                circular_notes.append(
                    f"    {CIRCULAR_MARKER}: {node} --> {child}"
                )
                continue

            new_path = path | {node}
            stack.append((child, cur_depth + 1, new_path))

    # 生成 Mermaid 代码
    lines = ["```mermaid", "flowchart TD"]

    # 节点定义
    for node in visited_nodes:
        nid = get_id(node)
        ver = versions.get(node, "")
        label = f"{node}@{ver}" if ver else node
        lines.append(f'    {nid}["{label}"]')

    # 边
    for src, tgt in rendered_edges:
        lines.append(f"    {get_id(src)} --> {get_id(tgt)}")

    # 循环依赖标注
    lines.extend(circular_notes)

    lines.append("```")
    return "\n".join(lines)
