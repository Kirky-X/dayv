#!/usr/bin/env python3
"""R15 SARIF 输出 + 弃用包检测回归测试（调研报告建议 15 验收项）。

验收点：
- SARIF 2.1.0 结构：runs[].tool.driver.rules / results（ruleId=CVE、
  level 按 severity 映射、message 含包名+修复版本）
- npm deprecated / crates yanked → parse 出 deprecated 标记
- 报告 deprecated_packages 段非空（含弃用包样例）
- health 维护维度对弃用扣分、建议显性提示
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

import report_renderer
import health_scorer
import dependency_analyzer as da
import npm
import crates


class TestSarif:
    REPORT = {
        "root_package": "demo",
        "vulnerabilities": [
            {
                "cve_id": "CVE-2024-1111",
                "package": "requests",
                "version": "2.3.0",
                "severity": "high",
                "description": "mock",
                "fixed_version": "2.31.0",
            },
            {
                "cve_id": "CVE-2024-2222",
                "package": "flask",
                "version": "1.0.0",
                "severity": "low",
                "description": "mock2",
                "fixed_version": None,
            },
        ],
    }

    def test_sarif_structure(self):
        sarif = report_renderer.render_sarif(self.REPORT)
        assert sarif["version"] == "2.1.0"
        run = sarif["runs"][0]
        assert run["tool"]["driver"]["name"] == "dayv"
        assert len(run["tool"]["driver"]["rules"]) == 2
        assert len(run["results"]) == 2

    def test_level_mapping_and_message(self):
        sarif = report_renderer.render_sarif(self.REPORT)
        results = sarif["runs"][0]["results"]
        by_rule = {r["ruleId"]: r for r in results}
        assert by_rule["CVE-2024-1111"]["level"] == "error"
        assert "2.31.0" in by_rule["CVE-2024-1111"]["message"]["text"]
        assert by_rule["CVE-2024-2222"]["level"] == "note"

    def test_rules_have_help_uri(self):
        sarif = report_renderer.render_sarif(self.REPORT)
        rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
        assert rule["helpUri"] == "https://osv.dev/vulnerability/CVE-2024-1111"

    def test_render_report_sarif_dispatch(self, tmp_path):
        out = tmp_path / "r.sarif"
        got = report_renderer.render_report(self.REPORT, str(out), fmt="sarif")
        assert got == str(out)
        import json

        assert json.loads(out.read_text(encoding="utf-8"))["version"] == "2.1.0"


class TestDeprecatedParse:
    def test_npm_latest_deprecated(self):
        data = {
            "name": "pkg",
            "dist-tags": {"latest": "2.0.0"},
            "versions": {
                "1.0.0": {"deprecated": "old"},
                "2.0.0": {"deprecated": "no longer maintained", "dist": {}},
            },
            "time": {},
        }
        assert npm.parse_package_info(data)["deprecated"] is True

    def test_npm_not_deprecated(self):
        data = {
            "name": "pkg",
            "dist-tags": {"latest": "2.0.0"},
            "versions": {
                "1.0.0": {"deprecated": "old"},  # 仅旧版本弃用不算
                "2.0.0": {"dist": {}},
            },
            "time": {},
        }
        assert npm.parse_package_info(data)["deprecated"] is False

    def test_crates_yanked(self):
        data = {
            "crate": {"name": "lib", "newest_version": "1.1.0"},
            "versions": [
                {"num": "1.1.0", "yanked": False, "license": "MIT"},
                {"num": "1.0.5", "yanked": True, "license": "MIT"},
            ],
        }
        assert crates.parse_package_info(data)["deprecated"] is True


class TestReportAndHealth:
    def test_report_dict_contains_deprecated(self, tmp_path):
        analyzer = da.DependencyAnalyzer(db_path=str(tmp_path / "g.db"))
        try:
            root = da.DependencyNode(
                name="demo", version="1.0", ecosystem="npm", is_root=True
            )
            dep = da.DependencyNode(
                name="old-pkg",
                version="1.0.0",
                ecosystem="npm",
                properties={"deprecated": True},
            )
            for p in (root, dep):
                analyzer.db.add_package(p)
            analyzer.db.set_deprecated("old-pkg", True)
            rows = analyzer.db.query_deprecated_packages()
            assert rows == [
                {"package": "old-pkg", "ecosystem": "npm", "version": "1.0.0"}
            ]
        finally:
            analyzer.close()

    def test_maintenance_penalty_and_suggestion(self):
        base_report = {
            "summary": {"total_packages": 3},
            "update_paths": [],
            "vulnerabilities": [],
            "conflicts": [],
        }
        base = health_scorer.score_health(base_report)
        with_dep = health_scorer.score_health(
            {
                **base_report,
                "deprecated_packages": [
                    {"package": "a", "ecosystem": "npm", "version": "1.0"},
                    {"package": "b", "ecosystem": "npm", "version": "2.0"},
                ],
            }
        )
        assert (
            with_dep["dimensions"]["maintenance_status"]
            == base["dimensions"]["maintenance_status"] - 20
        )
        assert any("弃用依赖" in s for s in with_dep["suggestions"])

    def test_penalty_capped(self):
        report = {
            "summary": {"total_packages": 10},
            "update_paths": [],
            "vulnerabilities": [],
            "conflicts": [],
            "deprecated_packages": [
                {"package": f"p{i}", "ecosystem": "npm", "version": "1"}
                for i in range(10)
            ],
        }
        result = health_scorer.score_health(report)
        # base 75 - 30（封顶）= 45
        assert result["dimensions"]["maintenance_status"] == 45.0
