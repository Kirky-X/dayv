#!/usr/bin/env python3
"""声明式规则引擎（调研建议 R11，参照 dependency-cruiser forbidden/allowed/
required 设计——吸收规则语义而非代码，评估对象是包级依赖图）。

规则文件 .dayv/rules.json::

    {
      "extends": "dayv:recommended",
      "rules": [
        {"name": "禁 GPL 系", "type": "forbidden", "severity": "error",
         "license": "^(GPL|AGPL|SSPL)"},
        {"name": "禁依赖内部黑名单", "type": "forbidden", "severity": "error",
         "to": "^(left-pad|request)$"},
        {"name": "生产禁 dev 组", "type": "forbidden", "severity": "warn",
         "group": "dev"}
      ]
    }

- type: forbidden（命中即违规）/ allowed（白名单，未命中任一 allowed 的包违规）/
  required（至少一个匹配，否则规则级违规）
- severity: error / warn / info / ignore（ignore 即关闭）
- 条件字段（全部可选，正则大小写不敏感）：to/from（包名）、license（许可证）、
  group（依赖组）、deprecated（bool）
- 内置预设 dayv:recommended：生产禁 dev 组 / 禁 GPL 系 / 弃用包防新增

独立 CLI：python rule_engine.py <rules.json> <deps_data.json> → 报告 +
存在 error 级违规时退出 1（CI 门禁可直连）。
"""

import json
import logging
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

RULE_TYPES = ("forbidden", "allowed", "required")
SEVERITIES = ("error", "warn", "info", "ignore")
RULE_FIELDS = {"name", "type", "severity", "to", "from", "license", "group", "deprecated", "message"}

# 内置预设（对应调研建议的三类开箱场景）
PRESETS: Dict[str, List[Dict[str, Any]]] = {
    "dayv:recommended": [
        {
            "name": "生产禁依赖 dev 组",
            "type": "forbidden",
            "severity": "warn",
            "group": "dev",
            "message": "生产依赖图不应包含 dev 依赖组的包",
        },
        {
            "name": "禁 GPL 系许可证",
            "type": "forbidden",
            "severity": "error",
            "license": "^(GPL|AGPL|SSPL)",
            "message": "GPL/AGPL/SSPL 系许可证有传染性，需法务评估",
        },
        {
            "name": "弃用包防新增",
            "type": "forbidden",
            "severity": "warn",
            "deprecated": True,
            "message": "上游已弃用（deprecated/yanked）的包不应新增引入",
        },
    ]
}


def load_rules(path: str) -> List[Dict[str, Any]]:
    """读取并校验规则文件；extends 解析内置预设；非法配置显式 ValueError。"""
    p = Path(path)
    if not p.is_file():
        raise ValueError(f"规则文件不存在: {path}")
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise ValueError(f"规则文件非法 JSON: {e}") from e
    if not isinstance(data, dict):
        raise ValueError(f"{path}: 顶层必须是对象")
    rules: List[Dict[str, Any]] = []

    extends = data.get("extends")
    if extends:
        if extends not in PRESETS:
            raise ValueError(
                f"{path}: 未知预设 {extends!r}（可用: {sorted(PRESETS)}）"
            )
        rules.extend([dict(r) for r in PRESETS[extends]])

    items = data.get("rules", [])
    if not isinstance(items, list):
        raise ValueError(f"{path}: rules 必须是数组")
    for i, rule in enumerate(items, 1):
        where = f"{path} rules[{i}]"
        if not isinstance(rule, dict):
            raise ValueError(f"{where}: 必须是对象")
        unknown = set(rule) - RULE_FIELDS
        if unknown:
            raise ValueError(f"{where}: 未知字段 {sorted(unknown)}")
        rtype = rule.get("type", "forbidden")
        if rtype not in RULE_TYPES:
            raise ValueError(f"{where}: type 必须是 {RULE_TYPES}")
        severity = rule.get("severity", "error")
        if severity not in SEVERITIES:
            raise ValueError(f"{where}: severity 必须是 {SEVERITIES}")
        entry = dict(rule)
        entry.setdefault("type", rtype)
        entry.setdefault("severity", severity)
        entry.setdefault("name", rule.get("name") or f"{rtype}-{i}")
        rules.append(entry)
    return rules


def _match(text: Optional[str], pattern: Optional[str]) -> bool:
    """包名/许可证正则匹配；无 pattern = 不过滤（恒真）。"""
    if pattern is None:
        return True
    if not text:
        return False
    return re.match(pattern, text, re.IGNORECASE) is not None


def _rule_matches_package(rule: Dict[str, Any], pkg: Dict[str, Any]) -> bool:
    """包级条件：license / group / deprecated / to（包名）。

    license 条件在许可证缺失（未采集/空串）时视为"无法判定 → 不命中"——
    空许可证触发违规会把未采集误报为不合规；UNKNOWN 单列语义由
    report --allowed-licenses 负责。
    """
    if "license" in rule:
        lic = pkg.get("license") or ""
        if not lic or not _match(lic, rule["license"]):
            return False
    if "group" in rule and (pkg.get("group") or "") != rule["group"]:
        return False
    if "deprecated" in rule and bool(pkg.get("deprecated", False)) != bool(
        rule["deprecated"]
    ):
        return False
    if "to" in rule and not _match(pkg.get("name", ""), rule["to"]):
        return False
    return True


def _rule_matches_edge(rule: Dict[str, Any], edge: Dict[str, Any]) -> bool:
    """边级条件：from（依赖方）+ to（被依赖方）。"""
    if "from" in rule and not _match(edge.get("source", ""), rule["from"]):
        return False
    if "to" in rule and not _match(edge.get("target", ""), rule["to"]):
        return False
    return True


def evaluate_rules(
    rules: List[Dict[str, Any]],
    deps_data: Dict[str, Any],
    license_map: Optional[Dict[str, str]] = None,
    deprecated_map: Optional[Dict[str, bool]] = None,
) -> List[Dict[str, Any]]:
    """评估规则 → violations 列表（带 severity，供 analyze-data/CI 统一消费）。

    - license 缺失（未采集）的包不触发 license 规则（无法判定≠违规，
      白名单合规用 report --allowed-licenses 的 UNKNOWN 单列语义）
    - allowed 语义：存在 allowed 规则时，未命中任何 allowed 的声明包违规
    - required 语义：无任何匹配项 → 单条规则级违规
    """
    license_map = license_map or {}
    deprecated_map = deprecated_map or {}
    packages = deps_data.get("packages", []) or []
    edges = deps_data.get("edges", []) or []

    enriched = []
    for pkg in packages:
        item = dict(pkg)
        if item.get("name") in license_map and not item.get("license"):
            item["license"] = license_map[item["name"]]
        item.setdefault(
            "deprecated", bool(deprecated_map.get(item.get("name", ""), False))
        )
        enriched.append(item)

    violations: List[Dict[str, Any]] = []

    def _violation(rule: Dict[str, Any], package: str, message: str) -> None:
        violations.append(
            {
                "rule": rule.get("name", "?"),
                "severity": rule.get("severity", "error"),
                "package": package,
                "message": message or rule.get("message", ""),
                "kind": "rule",
            }
        )

    active_rules = [r for r in rules if r.get("severity") != "ignore"]
    has_allowed = any(r["type"] == "allowed" for r in active_rules)

    for rule in active_rules:
        rtype = rule["type"]
        if rtype == "forbidden":
            if "from" in rule:
                # 边级规则
                for edge in edges:
                    if _rule_matches_edge(rule, edge):
                        tgt = next(
                            (
                                p.get("name", "")
                                for p in enriched
                                if p.get("name") == edge.get("target")
                            ),
                            edge.get("target", "?"),
                        )
                        _violation(
                            rule,
                            str(tgt),
                            rule.get("message")
                            or f"{edge.get('source')} → {edge.get('target')} 命中禁止规则",
                        )
            else:
                for pkg in enriched:
                    if _rule_matches_package(rule, pkg):
                        _violation(rule, pkg.get("name", "?"), rule.get("message", ""))
        elif rtype == "allowed":
            for pkg in enriched:
                if "license" in rule and not (pkg.get("license") or ""):
                    # 许可证缺失：无法判定白名单，不判违规（UNKNOWN 单列语义）
                    continue
                if not any(_rule_matches_package(r, pkg) for r in active_rules if r["type"] == "allowed"):
                    _violation(
                        rule,
                        pkg.get("name", "?"),
                        rule.get("message") or "不在 allowed 白名单内",
                    )
        elif rtype == "required":
            matched = any(
                _rule_matches_package(rule, pkg) for pkg in enriched
            ) or any(_rule_matches_edge(rule, e) for e in edges)
            if not matched:
                _violation(
                    rule,
                    "*",
                    rule.get("message") or "required 规则无任何匹配项",
                )

    # allowed 违规以首条 allowed 规则名义报一次即可（上面按每条 allowed 规则
    # 各报一次会重复——去重：同包同 severity 只保留第一条）
    deduped: List[Dict[str, Any]] = []
    seen: set = set()
    for v in violations:
        key = (v["rule"], v["package"], v["message"])
        if key in seen:
            continue
        seen.add(key)
        deduped.append(v)
    return deduped


def format_violations(violations: List[Dict[str, Any]]) -> str:
    if not violations:
        return "✅ 无规则违规"
    lines = [f"发现 {len(violations)} 条规则违规:"]
    order = {"error": 0, "warn": 1, "info": 2, "ignore": 3}
    for v in sorted(violations, key=lambda x: order.get(x["severity"], 9)):
        lines.append(
            f"  [{v['severity'].upper():<5}] {v['package']}: {v['rule']} — {v['message']}"
        )
    return "\n".join(lines)


def main(argv: List[str]) -> int:
    if len(argv) < 3:
        print("Usage: python rule_engine.py <rules.json> <deps_data.json>")
        return 1
    rules = load_rules(argv[1])
    data = json.loads(Path(argv[2]).read_text(encoding="utf-8"))
    violations = evaluate_rules(rules, data)
    print(format_violations(violations))
    if any(v["severity"] == "error" for v in violations):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
