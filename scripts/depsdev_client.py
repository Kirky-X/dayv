#!/usr/bin/env python3
"""deps.dev API 客户端（调研建议 R10：单一 API 对冲缺失生态解析 + findings +
Scorecard 三缺口）。

端点（全部免鉴权，明确允许客户端缓存）：
- v3 稳定 API：GetProject / GetDependencies（仅 npm/Cargo/Maven/PyPI）/
  GetRequirements（7 生态）/ GetScorecard（经 version 端点）
- v3alpha 实验 API：GetFindings（MALICIOUS/DEPRECATED/COOLDOWN/LOW_USAGE/
  REMEDIATION）——无稳定性承诺，只作增强信号

边界（调研实测）：
- GetDependencies 生态覆盖错位：packagist/rubygems/nuget 不在覆盖内，
  这些生态用 GetRequirements 数据本地合并
- PurlLookup 要求 purl 整体百分号编码（部分编码 404，用 purl.depsdev_purl_path）
- FAQ 未给量化限流：默认超时 + 单次调用，不做批量替换（250→5000 需先实测）

全部函数失败返回 None（调用方降级现有链路并显性提示），不抛异常穿透。
"""

import logging
from typing import Any, Callable, Dict, List, Optional

import ecosystem_registry as eco_reg

logger = logging.getLogger(__name__)

V3_BASE = "https://api.deps.dev/v3"
V3ALPHA_BASE = "https://api.deps.dev/v3alpha"

# GetDependencies 服务端解析的生态覆盖（deps.dev api.proto）。
# packagist/rubygems/nuget 不在覆盖内：这些生态走本地最小解析近似（直接依赖），
# GetRequirements 当前未接入解析链路（预留接口，供后续实现约束合并）。
DEPENDENCIES_ECOS = {"npm", "crates", "maven", "pypi"}

# GetFindings 的 finding_type 枚举（v3alpha）
FINDING_TYPES = (
    "MALICIOUS",
    "DEPRECATED",
    "COOLDOWN",
    "LOW_USAGE",
    "REMEDIATION",
)


def _default_get_json(url: str) -> dict:
    # 单次请求、15s 超时、无重试——deps.dev 是增强信号，降级路径必须快，
    # 不能走 utils.RequestClient 的 3 次重试（离线时最坏 ~15s×3 阻塞解析）
    import httpx

    resp = httpx.get(url, timeout=15.0, follow_redirects=True)
    resp.raise_for_status()
    return resp.json()


def _get_json(url: str, http_get: Optional[Callable[[str], dict]]) -> Optional[dict]:
    getter = http_get or _default_get_json
    try:
        data = getter(url)
    except Exception as e:
        logger.warning(f"deps.dev 请求失败（降级现有链路）: {url}: {e}")
        return None
    return data if isinstance(data, dict) else None


def _system(ecosystem: str) -> Optional[str]:
    return eco_reg.depsdev_system(ecosystem)


def _pkg_url(system: str, name: str, version: str, action: str = "") -> str:
    from urllib.parse import quote

    return (
        f"{V3_BASE}/systems/{system}/packages/{quote(name, safe='')}"
        f"/versions/{quote(version, safe='')}{action}"
    )


def get_dependencies(
    ecosystem: str,
    name: str,
    version: str,
    http_get: Optional[Callable[[str], dict]] = None,
) -> Optional[Dict[str, Any]]:
    """服务端解析传递依赖图（节点 nodes + 边 edges）；生态不支持或失败返回 None。"""
    system = _system(ecosystem)
    if not system or ecosystem not in DEPENDENCIES_ECOS:
        return None
    return _get_json(_pkg_url(system, name, version, ":dependencies"), http_get)


def get_requirements(
    ecosystem: str,
    name: str,
    version: str,
    http_get: Optional[Callable[[str], dict]] = None,
) -> Optional[Dict[str, Any]]:
    """7 生态未解析依赖约束（预留接口：当前解析链路未接入，不参与传递图增强）。"""
    system = _system(ecosystem)
    if not system:
        return None
    return _get_json(_pkg_url(system, name, version, ":requirements"), http_get)


def get_findings(
    ecosystem: str,
    name: str,
    version: str,
    http_get: Optional[Callable[[str], dict]] = None,
) -> Optional[List[Dict[str, Any]]]:
    """v3alpha GetFindings（实验 API，增强信号）；失败返回 None。"""
    system = _system(ecosystem)
    if not system:
        return None
    data = _get_json(_pkg_url(system, name, version, ":findings").replace("/v3/", "/v3alpha/", 1), http_get)
    if data is None:
        return None
    findings = data.get("findings", [])
    return findings if isinstance(findings, list) else None


def get_scorecard(
    ecosystem: str,
    name: str,
    version: str,
    http_get: Optional[Callable[[str], dict]] = None,
) -> Optional[Dict[str, Any]]:
    """OpenSSF Scorecard 评分（经 version 端点）；失败返回 None。"""
    system = _system(ecosystem)
    if not system:
        return None
    return _get_json(_pkg_url(system, name, version, ":scorecard"), http_get)


def get_project(
    project_key: str, http_get: Optional[Callable[[str], dict]] = None
) -> Optional[Dict[str, Any]]:
    """GetProject（repo key 如 github.com/owner/repo → Scorecard/别名等）。"""
    from urllib.parse import quote

    return _get_json(f"{V3_BASE}/projects/{quote(project_key, safe='')}", http_get)


def purl_lookup(
    purl: str, http_get: Optional[Callable[[str], dict]] = None
) -> Optional[Dict[str, Any]]:
    """PurlLookup：purl 整体百分号编码后查版本键（实测部分编码会 404）。"""
    import purl as purl_mod

    return _get_json(f"{V3_BASE}/purl/{purl_mod.depsdev_purl_path(purl)}", http_get)


def normalize_dependencies_payload(
    payload: Dict[str, Any], ecosystem: str
) -> tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """GetDependencies 响应 → (nodes, edges) deps_data 风格结构。

    响应 schema：{nodes: [{versionKey: {system, name, version}, ...}],
    edges: [{fromNode, toNode, requirement}, ...]}（node 以索引引用）。
    """
    nodes: List[Dict[str, Any]] = []
    node_entries = payload.get("nodes", []) or []
    for node in node_entries:
        vk = node.get("versionKey", {}) if isinstance(node, dict) else {}
        nodes.append(
            {
                "name": str(vk.get("name", "")),
                "version": str(vk.get("version", "")),
                "ecosystem": ecosystem,
            }
        )
    edges: List[Dict[str, Any]] = []
    for edge in payload.get("edges", []) or []:
        if not isinstance(edge, dict):
            continue
        try:
            src = node_entries[edge.get("fromNode", -1)]
            tgt = node_entries[edge.get("toNode", -1)]
        except (IndexError, TypeError):
            continue
        src_vk = (src or {}).get("versionKey", {})
        tgt_vk = (tgt or {}).get("versionKey", {})
        if not src_vk.get("name") or not tgt_vk.get("name"):
            continue
        edges.append(
            {
                "source": f"{src_vk['name']}@{src_vk.get('version', '')}",
                "target": f"{tgt_vk['name']}@{tgt_vk.get('version', '')}",
                "constraint": str(edge.get("requirement", "") or "*"),
            }
        )
    return nodes, edges
