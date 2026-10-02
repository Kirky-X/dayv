#!/usr/bin/env python3
"""许可证白名单/分类合规校验（调研建议 R8，参照 osv-scanner --licenses 白名单
+ trivy 分类映射）。

数据源：图 DB Package.license（enrich_licenses 回写的单一存储点）经
report_to_dict 的 license_info 列表暴露；查询失败/registry 未返回的包为
"UNKNOWN"——单列"无法校验"，不算通过也不算违规（规则 11 显性化）。

分类字典内置默认（宽松/弱 Copyleft/Copyleft），可用 YAML/JSON 文件覆盖或扩充
（--license-categories <file>）；表达式按 " OR " 分支取任一满足即合规。
"""

import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# 内置分类（SPDX id，大小写不敏感；子串匹配兼容 "GPL-3.0-only" 变体）
LICENSE_CATEGORIES: Dict[str, List[str]] = {
    "permissive": [
        "MIT", "APACHE-1.0", "APACHE-2.0", "BSD-2-CLAUSE", "BSD-3-CLAUSE",
        "BSD-4-CLAUSE", "BSD", "ISC", "0BSD", "ZLIB", "UNLICENSE", "WTFPL",
        "PSF", "PYTHON-2.0", "MS-PL", "POSTGRESQL", "BOOST-1.0", "CURL",
    ],
    "weak_copyleft": [
        "LGPL-2.0", "LGPL-2.1", "LGPL-3.0", "LGPL", "MPL-1.0", "MPL-1.1",
        "MPL-2.0", "MPL", "EPL-1.0", "EPL-2.0", "EPL", "CDDL", "CPL",
        "CEL", "RUBY", "ARTISTIC-2.0",
    ],
    "copyleft": [
        "GPL-1.0", "GPL-2.0", "GPL-3.0", "GPL", "AGPL-1.0", "AGPL-3.0",
        "AGPL", "SSPL", "OSL-3.0", "EUPL-1.2", "EUPL",
    ],
}

UNKNOWN = "UNKNOWN"


def load_custom_categories(path: str) -> Dict[str, List[str]]:
    """加载用户自定义分类覆盖（YAML/JSON 按扩展名分派；类别键必须是三类之一）。

    合并语义：自定义列表与内置同类别列表取并集（扩充场景常见——新增内部
    许可证 id），同名 id 以自定义类别为准。
    """
    p = Path(path)
    if not p.is_file():
        raise ValueError(f"许可证分类配置不存在: {path}")
    text = p.read_text(encoding="utf-8")
    if p.suffix.lower() in (".yaml", ".yml"):
        try:
            import yaml
        except ImportError as e:
            raise ValueError(
                "YAML 分类文件需要 pyyaml：pip install pyyaml（或改用 JSON 文件）"
            ) from e
        data = yaml.safe_load(text)
    else:
        import json

        data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError(f"{path}: 分类配置必须是 映射（类别 → id 列表）")
    unknown_keys = set(data) - set(LICENSE_CATEGORIES)
    if unknown_keys:
        raise ValueError(
            f"{path}: 未知类别 {sorted(unknown_keys)}（合法类别: "
            f"{sorted(LICENSE_CATEGORIES)}）"
        )
    merged: Dict[str, List[str]] = {
        k: list(v) for k, v in LICENSE_CATEGORIES.items()
    }
    for cat, ids in data.items():
        if not isinstance(ids, list):
            raise ValueError(f"{path}: 类别 {cat} 的值必须是 id 列表")
        for other in merged:
            merged[other] = [x for x in merged[other] if x not in map(str.upper, ids)]
        merged[cat] = merged[cat] + [str(x).upper() for x in ids]
    return merged


def classify_license(
    lic: str, custom: Optional[Dict[str, List[str]]] = None
) -> str:
    """许可证串 → 类别（permissive / weak_copyleft / copyleft / UNKNOWN）。

    匹配规则：SPDX id 以 token 边界出现在串中即视为该类别；串包含多个类别
    的 id（双许可）取最严格类别（保守合规立场）。
    """
    categories = custom or LICENSE_CATEGORIES
    lic_upper = (lic or "").strip().upper()
    if not lic_upper or lic_upper == UNKNOWN:
        return UNKNOWN
    tokens = set(re.findall(r"[A-Z0-9.\-]+", lic_upper))
    hit_categories = set()
    for cat, ids in categories.items():
        for lic_id in ids:
            for tok in tokens:
                # token 无空格（re 提取），变体覆盖 -only/-or-later/+（or-later）
                if (
                    tok == lic_id
                    or tok.startswith(lic_id + "-")
                    or tok.startswith(lic_id + "+")
                ):
                    hit_categories.add(cat)
                    break
    if not hit_categories:
        # 无法归类的非空许可证串：按 UNKNOWN 保守处理（显式单列而非默认通过）
        return UNKNOWN
    for strict in ("copyleft", "weak_copyleft", "permissive"):
        if strict in hit_categories:
            return strict
    return UNKNOWN


def _split_expression(lic: str) -> List[str]:
    """"MIT OR Apache-2.0" / "(MIT OR GPL-2.0) WITH Classpath" → 分支列表。"""
    cleaned = re.sub(r"\s+WITH\s+[A-Z0-9.\-]+", "", (lic or "").upper())
    branches = re.split(r"\s+OR\s+", cleaned)
    return [b.strip() for b in branches if b.strip()]


def evaluate_license_policy(
    license_info: List[Dict[str, Any]],
    allowed_licenses: List[str],
    custom: Optional[Dict[str, List[str]]] = None,
) -> Dict[str, Any]:
    """执行白名单策略校验。

    Args:
        license_info: report_to_dict 产出的 [{"package", "license"}, ...]
        allowed_licenses: 白名单 SPDX id（大小写不敏感）
        custom: 覆盖后的分类字典（可选，供 violations 标注类别）

    Returns:
        {
          "allowed": [白名单],
          "license_violations": [{package, license, category}],
          "unknown": [{package, license}],   # 无法校验，显式单列
          "checked": int,
        }
    """
    allowed = {a.strip().upper() for a in allowed_licenses if a.strip()}
    violations: List[Dict[str, Any]] = []
    unknown: List[Dict[str, Any]] = []
    checked = 0
    for item in license_info or []:
        pkg = item.get("package", "") if isinstance(item, dict) else str(item)
        lic = (item.get("license", "") if isinstance(item, dict) else "") or ""
        if not lic or lic.upper() == UNKNOWN:
            unknown.append({"package": pkg, "license": lic or UNKNOWN})
            continue
        checked += 1
        # 表达式任一分支的任一 token 命中白名单即合规
        ok = False
        for branch in _split_expression(lic):
            tokens = set(re.findall(r"[A-Z0-9.\-]+", branch))
            if tokens & allowed:
                ok = True
                break
        if ok:
            continue
        violations.append(
            {
                "package": pkg,
                "license": lic,
                "category": classify_license(lic, custom),
            }
        )
    return {
        "allowed": sorted(allowed),
        "license_violations": violations,
        "unknown": unknown,
        "checked": checked,
    }
