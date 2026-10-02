#!/usr/bin/env python3
"""
SBOM Generator - 软件物料清单生成器
生成 SPDX 2.3 JSON 格式的 SBOM

SPDX 2.3 schema 参考: https://spdx.github.io/spdx-spec/

输入: deps_data.json schema 的 packages + edges
输出: SPDX 2.3 JSON dict / 文件
"""

import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

import re

import ecosystem_registry as eco_reg
import purl as purl_mod

logger = logging.getLogger(__name__)

# ============ SPDX 2.3 常量 ============

SPDX_VERSION = "SPDX-2.3"
SPDX_DATA_LICENSE = "CC0-1.0"
SPDX_LICENSE_LIST_VERSION = "3.21"
SPDX_DOC_ID = "SPDXRef-DOCUMENT"

# 默认 Supplier（无供应商信息时）
DEFAULT_SUPPLIER = "NOASSERTION"

# 默认 LicenseConcluded（无许可证信息时）
DEFAULT_LICENSE = "NOASSERTION"


def safe_filename(name: str) -> str:
    """project_name → 安全文件名分量（拦截 ../ 路径穿越，默认输出名专用）。"""
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "-", name).strip(".") or "project"
    return cleaned.replace("..", "-")


# ============ 工具函数 ============


def _make_spdx_id(name: str) -> str:
    """
    生成 Package SPDXID: SPDXRef-Package-{sanitized_name}

    SPDXID 必须匹配 [A-Za-z0-9.-]+ 字符集，非法字符替换为 -
    """
    safe = "".join(c if c.isalnum() or c in ".-" else "-" for c in name)
    # 避免连续 -
    while "--" in safe:
        safe = safe.replace("--", "-")
    return f"SPDXRef-Package-{safe}"


def _make_download_location(name: str, ecosystem: str) -> str:
    """按 ecosystem 生成 downloadLocation URL（基址来自 ecosystem_registry）"""
    base = eco_reg.registry_base_url(ecosystem)
    if not base:
        return "NOASSERTION"
    return f"{base}{name}"


def _format_created_timestamp() -> str:
    """生成 ISO 8601 UTC 时间戳"""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _make_document_namespace(project_name: str) -> str:
    """
    生成唯一 DocumentNamespace

    格式: https://dayv.local/{project_name}/{uuid}
    SPDX 规范要求 DocumentNamespace 必须唯一
    """
    safe_name = "".join(c if c.isalnum() or c in ".-" else "-" for c in project_name)
    return f"https://dayv.local/{safe_name}/{uuid.uuid4()}"


# ============ 主函数 ============


def generate_sbom(packages: List[Dict[str, Any]],
                  edges: List[Dict[str, Any]],
                  project_name: str) -> Dict[str, Any]:
    """
    生成 SPDX 2.3 SBOM 字典

    Args:
        packages: 依赖包列表，每个元素 schema:
            {name, version, ecosystem, is_root?, license?}
        edges: 依赖关系列表，每个元素 schema:
            {source, target, constraint?}
        project_name: 项目名（用于 DocumentName）

    Returns:
        SPDX 2.3 格式的 SBOM dict
    """
    # 构建 Packages
    packages_sbom = []
    name_to_spdxid: Dict[str, str] = {}

    for pkg in packages:
        name = pkg.get("name", "unknown")
        version = pkg.get("version", "")
        ecosystem = pkg.get("ecosystem", "")
        license_info = pkg.get("license", "")

        spdx_id = _make_spdx_id(name)
        # 处理重名包（同名不同版本）：追加 -v{version}
        if spdx_id in name_to_spdxid.values():
            spdx_id = _make_spdx_id(f"{name}-{version}")

        if name not in name_to_spdxid:
            # 首见版本保留映射：DESCRIBES/边指向首版，后续版本仅占位
            name_to_spdxid[name] = spdx_id

        pkg_entry = {
            "Name": name,
            "SPDXID": spdx_id,
            "VersionInfo": version,
            "DownloadLocation": _make_download_location(name, ecosystem),
            "FilesAnalyzed": False,
            "LicenseConcluded": license_info if license_info else DEFAULT_LICENSE,
            "Supplier": DEFAULT_SUPPLIER,
        }
        # purl externalRefs：下游（osv-scanner --sbom / trivy sbom）靠它识别包。
        # purl 构造不出（生态未知）时省略字段，不写假值。
        purl_str = purl_mod.make_purl(name, ecosystem, version or None)
        if purl_str:
            pkg_entry["externalRefs"] = [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": purl_str,
                }
            ]
        packages_sbom.append(pkg_entry)

    # 构建 Relationships
    relationships: List[Dict[str, str]] = []

    # 1. DESCRIBES: 文档描述根包
    root_pkgs = [p for p in packages if p.get("is_root")]
    if root_pkgs:
        root_name = root_pkgs[0]["name"]
        relationships.append({
            "SPDXElementID": SPDX_DOC_ID,
            "RelationshipType": "DESCRIBES",
            "RelatedSPDXElement": name_to_spdxid.get(root_name, _make_spdx_id(root_name)),
        })
    elif packages:
        # 无 is_root 标记，描述第一个包
        first_name = packages[0]["name"]
        relationships.append({
            "SPDXElementID": SPDX_DOC_ID,
            "RelationshipType": "DESCRIBES",
            "RelatedSPDXElement": name_to_spdxid.get(first_name, _make_spdx_id(first_name)),
        })

    # 2. DEPENDS_ON: 来自 edges
    for edge in edges:
        src = edge.get("source", "")
        tgt = edge.get("target", "")
        if src in name_to_spdxid and tgt in name_to_spdxid:
            relationships.append({
                "SPDXElementID": name_to_spdxid[src],
                "RelationshipType": "DEPENDS_ON",
                "RelatedSPDXElement": name_to_spdxid[tgt],
            })
        else:
            logger.warning(
                f"跳过依赖关系 {src} -> {tgt}: 找不到对应 SPDXID"
            )

    return {
        "SPDXVersion": SPDX_VERSION,
        "DataLicense": SPDX_DATA_LICENSE,
        "SPDXID": SPDX_DOC_ID,
        "DocumentName": project_name,
        "DocumentNamespace": _make_document_namespace(project_name),
        "CreationInfo": {
            "Created": _format_created_timestamp(),
            "Creators": ["Tool: dayv-dependency-analyzer-1.0"],
            "LicenseListVersion": SPDX_LICENSE_LIST_VERSION,
        },
        "Packages": packages_sbom,
        "Relationships": relationships,
    }


def write_sbom(packages: List[Dict[str, Any]],
               edges: List[Dict[str, Any]],
               project_name: str,
               output_path: str = None) -> str:
    """
    生成 SBOM 并写入 .spdx.json 文件

    Args:
        packages: 依赖包列表
        edges: 依赖关系列表
        project_name: 项目名
        output_path: 输出路径，None 时默认为 {project_name}-sbom.spdx.json

    Returns:
        实际写入的文件路径
    """
    sbom = generate_sbom(packages, edges, project_name)

    if output_path is None:
        output_path = f"{safe_filename(project_name)}-sbom.spdx.json"

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    with output.open('w', encoding='utf-8') as f:
        json.dump(sbom, f, indent=2, ensure_ascii=False)

    logger.info(f"SBOM 已生成: {output_path}")
    return output_path


# ============ CycloneDX 1.5（R6，复用 purl 模块） ============

CDX_SPEC_VERSION = "1.5"


def _cdx_bom_ref(name: str, version: str) -> str:
    """bom-ref： Synthetic identifier (must be unique within the document)."""
    safe = "".join(c if c.isalnum() or c in ".-_" else "-" for c in f"{name}@{version}")
    return f"dayv:{safe}"


def generate_cyclonedx(packages: List[Dict[str, Any]],
                       edges: List[Dict[str, Any]],
                       project_name: str) -> Dict[str, Any]:
    """
    Generate CycloneDX 1.5 JSON dictionary.

    - Root package → metadata.component (type=application); remaining packages → components[]
    - Each component carries purl (single-point module construction); license attached when present
    - dependencies[]: ref → dependsOn three-part assembly (SBOM is positioned as an interchange format,
      authoritative data still lives in the graph DB)
    """
    components: List[Dict[str, Any]] = []
    ref_by_name: Dict[str, str] = {}
    root_component: Dict[str, Any] = {}

    for pkg in packages:
        name = pkg.get("name", "unknown")
        version = str(pkg.get("version", "") or "")
        ecosystem = pkg.get("ecosystem", "")
        license_info = pkg.get("license", "")

        purl_str = purl_mod.make_purl(name, ecosystem, version or None)
        ref = _cdx_bom_ref(name, version)
        component: Dict[str, Any] = {
            "type": "library",
            "bom-ref": ref,
            "name": name,
            "version": version,
        }
        if purl_str:
            component["purl"] = purl_str
        if license_info and license_info.upper() not in ("UNKNOWN", "NOASSERTION"):
            # SPDX 表达式（含 OR/AND/WITH/括号）必须走 expression 字段，
            # id 只允许单个 SPDX license id（规范校验器会拒绝表达式写 id）
            if re.search(r"\s+(?:OR|AND|WITH)\s+|\(", license_info):
                component["licenses"] = [{"expression": license_info}]
            else:
                component["licenses"] = [{"license": {"id": license_info}}]

        if pkg.get("is_root") and not root_component:
            root_component = {**component, "type": "application"}
        else:
            components.append(component)
            ref_by_name[name] = ref

    if not root_component and packages:
        first = packages[0]
        ref = _cdx_bom_ref(first.get("name", "unknown"), str(first.get("version", "") or ""))
        root_component = {
            "type": "application",
            "bom-ref": ref,
            "name": first.get("name", "unknown"),
            "version": str(first.get("version", "") or ""),
        }

    # dependencies[]: ref → dependsOn (src side is the root when the name is not in the component table)
    depends_map: Dict[str, List[str]] = {}
    for edge in edges:
        src = edge.get("source", "")
        tgt = edge.get("target", "")
        src_ref = ref_by_name.get(src, root_component.get("bom-ref", ""))
        tgt_ref = ref_by_name.get(tgt)
        if not src_ref or tgt_ref is None:
            logger.warning(f"Skipping CycloneDX dependency relationship {src} -> {tgt}: missing corresponding bom-ref")
            continue
        depends_map.setdefault(src_ref, [])
        if tgt_ref not in depends_map[src_ref]:
            depends_map[src_ref].append(tgt_ref)

    dependencies = []
    all_refs = [root_component["bom-ref"]] + [c["bom-ref"] for c in components]
    for ref in all_refs:
        dependencies.append({"ref": ref, "dependsOn": depends_map.get(ref, [])})

    return {
        "bomFormat": "CycloneDX",
        "specVersion": CDX_SPEC_VERSION,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": _format_created_timestamp(),
            "tools": [{"vendor": "dayv", "name": "dayv-dependency-analyzer"}],
            "component": root_component,
        },
        "components": components,
        "dependencies": dependencies,
    }


def write_cyclonedx(packages: List[Dict[str, Any]],
                    edges: List[Dict[str, Any]],
                    project_name: str,
                    output_path: str = None) -> str:
    """Generate CycloneDX SBOM and write a .cdx.json file (usable for re-scanning by trivy sbom / osv-scanner)."""
    cdx = generate_cyclonedx(packages, edges, project_name)
    if output_path is None:
        output_path = f"{safe_filename(project_name)}-sbom.cdx.json"
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8") as f:
        json.dump(cdx, f, indent=2, ensure_ascii=False)
    logger.info(f"CycloneDX SBOM generated: {output_path}")
    return output_path
