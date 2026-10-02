#!/usr/bin/env python3
"""已知违规基线 + --ignore-known（调研建议 R12，参照 dependency-cruiser
--baseline/--ignore-known 的违规债务管理语义）。

基线文件 .dayv-known-violations.json::

    {
      "generated_at": "2026-10-03T…",
      "violations": ["pkg:CVE-2024-1111", "left-pad:conflict:version_mismatch", …]
    }

- 键 = 包名:类别:标识（vulnerability 用 CVE id、conflict 用 conflict_type、
  rule 用规则名）——比"包名+违规类型"更细粒度，避免同包多 CVE 互相吞没
- shrink-only 等价：写基线时若旧基线含新扫描没有的条目，显性列出
  （可能已修复，提示人工确认——防基线沦为永久豁免，caveat）
- --ignore-known：命中基线的违规单独列出，退出码判定只看新增
"""

import json
import logging
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

DEFAULT_BASELINE_FILE = ".dayv-known-violations.json"


def violation_key(v: Dict[str, Any]) -> str:
    """违规 → 稳定键。

    支持三种输入形态：
    - {"package", "cve_id", …}（漏洞）
    - {"package", "conflict_type", …}（冲突）
    - {"package", "rule", "kind": "rule"}（规则违规）
    """
    package = str(v.get("package", "?"))
    if "cve_id" in v:
        return f"{package}:vulnerability:{v.get('cve_id', '?')}"
    if "conflict_type" in v:
        return f"{package}:conflict:{v.get('conflict_type', '?')}"
    return f"{package}:rule:{v.get('rule', v.get('id', '?'))}"


def violations_from_report(report_dict: Dict[str, Any]) -> List[Dict[str, Any]]:
    """从报告 dict 收集违规（冲突 + 漏洞 + 规则违规如有）。"""
    violations: List[Dict[str, Any]] = []
    for c in report_dict.get("conflicts", []) or []:
        violations.append(
            {
                "package": c.get("package", "?"),
                "conflict_type": c.get("conflict_type", "?"),
                "severity": c.get("severity", "high"),
            }
        )
    for v in report_dict.get("vulnerabilities", []) or []:
        violations.append(
            {
                "package": v.get("package", "?"),
                "cve_id": v.get("cve_id", "?"),
                "severity": v.get("severity", "medium"),
            }
        )
    for v in report_dict.get("rule_violations", []) or []:
        violations.append(
            {
                "package": v.get("package", "?"),
                "rule": v.get("rule", "?"),
                "severity": v.get("severity", "warn"),
            }
        )
    return violations


def save_baseline(
    violations: List[Dict[str, Any]], path: str
) -> Tuple[List[str], List[str]]:
    """写基线（shrink-only 检查）。

    Returns:
        (new_keys, vanished)：vanished = 旧基线有而新扫描没有的键
        （基线非收缩变更，可能已修复——调用方显性提示，不阻断）。
    """
    p = Path(path)
    old_keys: List[str] = []
    if p.is_file():
        try:
            old = json.loads(p.read_text(encoding="utf-8"))
            old_keys = [str(k) for k in old.get("violations", [])]
        except Exception as e:
            logger.warning(f"旧基线解析失败（按空基线处理）: {e}")

    new_keys = sorted({violation_key(v) for v in violations})
    vanished = [k for k in old_keys if k not in set(new_keys)]

    payload = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "violations": new_keys,
    }
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return new_keys, vanished


def load_baseline(path: str) -> List[str]:
    """读基线键列表；文件缺失/损坏显式报错（显式传入即应可用）。"""
    p = Path(path)
    if not p.is_file():
        raise ValueError(f"基线文件不存在: {path}")
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise ValueError(f"基线文件非法 JSON: {e}") from e
    keys = data.get("violations", [])
    if not isinstance(keys, list):
        raise ValueError(f"{path}: violations 必须是数组")
    return [str(k) for k in keys]


def split_known(
    violations: List[Dict[str, Any]], baseline_keys: List[str]
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """违规分为（新增, 已知）。已知项不参与 --exit-code 退出判定（只对新增 fail）。"""
    known_keys = set(baseline_keys)
    new: List[Dict[str, Any]] = []
    known: List[Dict[str, Any]] = []
    for v in violations:
        (known if violation_key(v) in known_keys else new).append(v)
    return new, known
