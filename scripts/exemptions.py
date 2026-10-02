#!/usr/bin/env python3
"""漏洞豁免清单（调研建议 R7，参照 osv-scanner [[IgnoredVulns]] 语义）。

配置来源（两路，可叠加）：
1. .dayv.toml（项目根或显式 --config）::

       [[ignored_vulns]]
       id = "GHSA-xxxx-xxxx-xxxx"     # CVE 或 OSV/GHSA id，命中 alias 连带生效
       reason = "dev 依赖不可达"        # 必填，进报告 ignored_vulnerabilities 段
       ignore_until = "2026-12-31"     # 可选；过期（< 当天）自动恢复告警

2. deps_data.json 内联数组::

       "ignored_vulns": [{"id": "CVE-...", "reason": "...", "ignore_until": "..."}]

显性化约定（规则 11）：被豁免漏洞不静默消失——报告新增 ignored_vulnerabilities
段逐条列出 reason 与过期日期；过期豁免自动失效回到 vulnerabilities。
package_overrides 语义未定义，本版不实现（预留键名，解析到即显式报错）。
"""

import logging
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

CONFIG_FILE_NAME = ".dayv.toml"


@dataclass
class ExemptVuln:
    """一条豁免：漏洞 id（含 alias 连带）+ 必填理由 + 可选过期日。"""

    id: str
    reason: str
    ignore_until: Optional[str] = None  # ISO 日期 "YYYY-MM-DD"


def _parse_toml(path: Path) -> dict:
    try:
        import tomllib
    except ImportError:
        import tomli as tomllib  # type: ignore
    try:
        with path.open("rb") as f:
            return tomllib.load(f)
    except Exception as e:
        raise ValueError(f"豁免配置解析失败 {path}: {e}") from e


def from_raw_list(items: Any, source: str) -> List[ExemptVuln]:
    """从 dict 数组构造豁免（toml [[ignored_vulns]] / deps_data 内联合用）。

    非法条目（缺 id/reason、日期格式错、未知键）显式抛 ValueError——配置错误
    必须让调用方失败，不能静默忽略一条豁免（静默 = 误报漏洞被隐藏）。
    """
    exempt: List[ExemptVuln] = []
    if not items:
        return exempt
    if not isinstance(items, list):
        raise ValueError(f"{source}: ignored_vulns 必须是数组")
    for i, item in enumerate(items, 1):
        where = f"{source} ignored_vulns[{i}]"
        if not isinstance(item, dict):
            raise ValueError(f"{where}: 必须是对象")
        unknown = set(item) - {"id", "reason", "ignore_until"}
        if unknown:
            raise ValueError(f"{where}: 未知字段 {sorted(unknown)}")
        vuln_id = str(item.get("id", "")).strip()
        reason = str(item.get("reason", "")).strip()
        if not vuln_id or not reason:
            raise ValueError(f"{where}: id 与 reason 必填")
        until = item.get("ignore_until")
        if until is not None:
            until = str(until).strip()
            try:
                date.fromisoformat(until)
            except ValueError as e:
                raise ValueError(f"{where}: ignore_until 需为 YYYY-MM-DD: {until}") from e
        exempt.append(ExemptVuln(id=vuln_id, reason=reason, ignore_until=until))
    return exempt


def load_exemptions(config_path: str) -> List[ExemptVuln]:
    """读取 .dayv.toml 的 [[ignored_vulns]]；文件不存在报错（显式传入即应存在）。"""
    path = Path(config_path)
    if not path.is_file():
        raise ValueError(f"豁免配置不存在: {config_path}")
    data = _parse_toml(path)
    if data.get("package_overrides"):
        raise ValueError(
            f"{config_path}: [[package_overrides]] 语义未定义（当前版本仅支持 "
            "[[ignored_vulns]]），请删除该段或改用 ignored_vulns"
        )
    return from_raw_list(data.get("ignored_vulns"), str(path))


def find_config_file(search_dir) -> Optional[Path]:
    """在目录（及其上层，最多 3 级）查找 .dayv.toml；找不到返回 None。"""
    current = Path(search_dir).resolve()
    for _ in range(3):
        candidate = current / CONFIG_FILE_NAME
        if candidate.is_file():
            return candidate
        if current.parent == current:
            break
        current = current.parent
    return None


def from_deps_data(data: dict) -> List[ExemptVuln]:
    """deps_data.json 的内联 ignored_vulns 数组 → 豁免列表（无该键返回空）。"""
    return from_raw_list((data or {}).get("ignored_vulns"), "deps_data")


def is_expired(exempt: ExemptVuln, today: Optional[date] = None) -> bool:
    """豁免是否已过期（ignore_until < today）。无过期日 = 永久有效。"""
    if not exempt.ignore_until:
        return False
    today = today or date.today()
    return date.fromisoformat(exempt.ignore_until) < today


def apply_exemptions(
    vulns: List[Any],
    exemptions: List[ExemptVuln],
    today: Optional[date] = None,
) -> Tuple[List[Any], List[Dict[str, str]]]:
    """把漏洞分为（未豁免, 已豁免）。

    命中规则：vuln.cve_id 或其 aliases（OSV alias 连带，如 GHSA↔CVE）等于
    豁免 id。已过期的豁免不生效——对应漏洞留在 active（自动恢复告警）。

    Returns:
        (active_vulns, ignored_entries)
        ignored_entries 元素:
        {"cve_id", "package", "reason", "ignore_until", "matched_via"}
        matched_via 说明命中路径（直接 id 或经由哪个 alias），供报告审计。
    """
    by_id = {}
    for e in exemptions:
        by_id.setdefault(e.id, []).append(e)

    active: List[Any] = []
    ignored: List[Dict[str, str]] = []
    for v in vulns:
        ids = [v.cve_id] + list(getattr(v, "aliases", []) or [])
        hit = None
        matched_via = ""
        for vid in ids:
            for e in by_id.get(vid, []):
                if not is_expired(e, today):
                    hit = e
                    matched_via = vid
                    break
            if hit:
                break
        if hit is None:
            active.append(v)
        else:
            ignored.append(
                {
                    "cve_id": v.cve_id,
                    "package": v.package,
                    "reason": hit.reason,
                    "ignore_until": hit.ignore_until or "",
                    "matched_via": matched_via,
                }
            )
    return active, ignored
