#!/usr/bin/env python3
"""R11 规则引擎 + R12 违规基线回归测试（调研报告建议 11/12 验收项）。

验收点：
- 样例规则命中时 violations 含对应条目且 severity 正确
- extends 内置预设（禁 dev 组/禁 GPL/弃用包防新增）
- 首扫生成基线 → --ignore-known 只报新增
- 基线非收缩变更显性提示（旧条目消失）
"""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

import rule_engine
import violation_baseline as vb


RULES = {
    "rules": [
        {"name": "禁 left-pad", "type": "forbidden", "severity": "error",
         "to": "^left-pad$"},
        {"name": "仅 MIT 系", "type": "allowed", "severity": "warn",
         "license": "^(MIT|Apache|BSD|ISC)"},
        {"name": "必须含 web 框架", "type": "required", "severity": "info",
         "to": "^(flask|fastapi|express)"},
    ]
}

DEPS = {
    "packages": [
        {"name": "app", "version": "1.0", "is_root": True},
        {"name": "left-pad", "version": "1.3.0", "license": "MIT", "group": "dependencies"},
        {"name": "gpl-lib", "version": "2.0", "license": "GPL-3.0-only"},
        {"name": "unknown-lic", "version": "0.1", "license": ""},
    ],
    "edges": [
        {"source": "app", "target": "left-pad", "constraint": "^1.3.0"},
        {"source": "gpl-lib", "target": "left-pad", "constraint": "*"},
    ],
}


class TestRuleEngine:
    def test_forbidden_hit_with_severity(self):
        violations = rule_engine.evaluate_rules(
            [r for r in RULES["rules"] if r["type"] == "forbidden"], DEPS
        )
        assert any(
            v["package"] == "left-pad" and v["severity"] == "error"
            for v in violations
        )

    def test_license_condition_and_unknown_skip(self):
        forbidden = {
            "name": "禁 GPL", "type": "forbidden", "severity": "error",
            "license": "^GPL",
        }
        violations = rule_engine.evaluate_rules([forbidden], DEPS)
        assert [v["package"] for v in violations] == ["gpl-lib"]  # 空许可证不触发

    def test_required_missing_violates(self):
        required = {
            "name": "必须含框架", "type": "required", "severity": "info",
            "to": "^(flask|fastapi)$",
        }
        violations = rule_engine.evaluate_rules([required], DEPS)
        assert len(violations) == 1 and violations[0]["package"] == "*"

    def test_allowed_whitelist(self):
        allowed = {
            "name": "仅 MIT 系", "type": "allowed", "severity": "warn",
            "license": "^(MIT|Apache|BSD|ISC)",
        }
        violations = rule_engine.evaluate_rules([allowed], DEPS)
        offenders = {v["package"] for v in violations}
        # gpl-lib 许可证不匹配白名单；unknown-lic 许可证为空 → 不判定
        assert offenders == {"gpl-lib"}

    def test_edge_from_condition(self):
        rule = {
            "name": "gpl-lib 不得依赖", "type": "forbidden", "severity": "error",
            "from": "^gpl-lib$", "to": ".*",
        }
        violations = rule_engine.evaluate_rules([rule], DEPS)
        assert any(v["package"] == "left-pad" for v in violations)

    def test_deprecated_condition(self):
        rule = {
            "name": "弃用包防新增", "type": "forbidden", "severity": "warn",
            "deprecated": True,
        }
        violations = rule_engine.evaluate_rules(
            [rule], DEPS, deprecated_map={"left-pad": True}
        )
        assert any(v["package"] == "left-pad" for v in violations)

    def test_preset_recommended(self):
        rules = rule_engine.load_rules(
            _tmp(json.dumps({"extends": "dayv:recommended", "rules": []}))
        )
        assert len(rules) == 3
        violations = rule_engine.evaluate_rules(rules, DEPS)
        packages = {v["package"] for v in violations}
        assert "gpl-lib" in packages  # 禁 GPL 预设命中

    def test_invalid_rules_rejected(self):
        bad = [
            {"type": "unknown-type"},
            {"severity": "fatal"},
            {"no_such_field": 1},
        ]
        for rule in bad:
            with pytest.raises(ValueError):
                rule_engine.load_rules(_tmp(json.dumps({"rules": [rule]})))


class TestViolationBaseline:
    def test_key_forms(self):
        assert (
            vb.violation_key({"package": "req", "cve_id": "CVE-1"})
            == "req:vulnerability:CVE-1"
        )
        assert (
            vb.violation_key({"package": "a", "conflict_type": "version_mismatch"})
            == "a:conflict:version_mismatch"
        )
        assert (
            vb.violation_key({"package": "x", "rule": "禁 GPL", "kind": "rule"})
            == "x:rule:禁 GPL"
        )

    def test_baseline_write_and_split(self, tmp_path):
        first = [
            {"package": "req", "cve_id": "CVE-A"},
            {"package": "req", "cve_id": "CVE-B"},
        ]
        keys, vanished = vb.save_baseline(first, str(tmp_path / "b.json"))
        assert len(keys) == 2 and vanished == []

        # 引入新漏洞 + 旧漏洞修复
        second = [
            {"package": "req", "cve_id": "CVE-A"},
            {"package": "req", "cve_id": "CVE-C"},
        ]
        new_items, known_items = vb.split_known(
            second, vb.load_baseline(str(tmp_path / "b.json"))
        )
        assert [v["cve_id"] for v in new_items] == ["CVE-C"]
        assert [v["cve_id"] for v in known_items] == ["CVE-A"]

    def test_shrink_check_reports_vanished(self, tmp_path):
        vb.save_baseline(
            [{"package": "req", "cve_id": "CVE-A"},
             {"package": "req", "cve_id": "CVE-B"}],
            str(tmp_path / "b.json"),
        )
        # 新扫描只剩 CVE-A：CVE-B 消失 → 非收缩变更提示
        keys, vanished = vb.save_baseline(
            [{"package": "req", "cve_id": "CVE-A"}], str(tmp_path / "b.json")
        )
        assert vanished == ["req:vulnerability:CVE-B"]

    def test_load_baseline_missing_raises(self, tmp_path):
        with pytest.raises(ValueError):
            vb.load_baseline(str(tmp_path / "nope.json"))


def _tmp(content: str) -> str:
    import tempfile
    from pathlib import Path

    f = Path(tempfile.mkdtemp(prefix="dayv_r11_")) / "rules.json"
    f.write_text(content, encoding="utf-8")
    return str(f)
