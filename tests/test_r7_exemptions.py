#!/usr/bin/env python3
"""R7 漏洞豁免清单回归测试（调研报告建议 7 验收项）。

验收点：
- 豁免一条 CVE 后 vulnerabilities 不含它、ignored_vulnerabilities 含它
- 过期（ignore_until < today）自动恢复告警（回到 vulnerabilities）
- alias 连带命中（豁免 GHSA id 过滤对应 CVE 漏洞）
- 配置非法显式报错（缺 reason / 坏日期 / 未知字段 / package_overrides）
"""

import os
import sys
from datetime import date, timedelta

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

import exemptions as ex
from dependency_analyzer import SecurityVulnerability, SeverityLevel


def _vuln(cve="CVE-2024-1111", pkg="requests", aliases=None):
    return SecurityVulnerability(
        package=pkg,
        version="2.3.0",
        severity=SeverityLevel.HIGH,
        cve_id=cve,
        description="mock",
        aliases=aliases or [],
    )


class TestLoadExemptions:
    def test_load_toml(self, tmp_path):
        cfg = tmp_path / ".dayv.toml"
        cfg.write_text(
            '[[ignored_vulns]]\nid = "CVE-2024-1111"\nreason = "dev-only"\n'
            'ignore_until = "2027-12-31"\n',
            encoding="utf-8",
        )
        got = ex.load_exemptions(str(cfg))
        assert got == [
            ex.ExemptVuln(id="CVE-2024-1111", reason="dev-only", ignore_until="2027-12-31")
        ]

    def test_missing_file_raises(self, tmp_path):
        with pytest.raises(ValueError):
            ex.load_exemptions(str(tmp_path / "nope.toml"))

    def test_invalid_entries_raise(self, tmp_path):
        bad = [
            '[[ignored_vulns]]\nid = "CVE-X"\n',  # 缺 reason
            '[[ignored_vulns]]\nid = "CVE-X"\nreason = "r"\nignore_until = "2027/01/01"\n',  # 坏日期
            '[[ignored_vulns]]\nid = "CVE-X"\nreason = "r"\nfoo = 1\n',  # 未知字段
            "[[package_overrides]]\nname = 'x'\n",  # 语义未定义显式拒绝
        ]
        for i, content in enumerate(bad):
            cfg = tmp_path / f".dayv{i}.toml"
            cfg.write_text(content, encoding="utf-8")
            with pytest.raises(ValueError):
                ex.load_exemptions(str(cfg))

    def test_deps_data_inline(self):
        got = ex.from_deps_data(
            {"ignored_vulns": [{"id": "GHSA-x", "reason": "r"}]}
        )
        assert got[0].id == "GHSA-x"

    def test_find_config_walks_up(self, tmp_path):
        (tmp_path / ".dayv.toml").write_text("", encoding="utf-8")
        sub = tmp_path / "a" / "b"
        sub.mkdir(parents=True)
        found = ex.find_config_file(sub)
        assert found is not None and found.name == ".dayv.toml"


class TestApplyExemptions:
    def test_split_active_ignored(self):
        active, ignored = ex.apply_exemptions(
            [_vuln("CVE-A"), _vuln("CVE-B", pkg="flask")],
            [ex.ExemptVuln(id="CVE-A", reason="r", ignore_until="2027-01-01")],
            today=date(2026, 10, 3),
        )
        assert [v.cve_id for v in active] == ["CVE-B"]
        assert ignored == [
            {
                "cve_id": "CVE-A",
                "package": "requests",
                "reason": "r",
                "ignore_until": "2027-01-01",
                "matched_via": "CVE-A",
            }
        ]

    def test_expired_exemption_recovers_alert(self):
        yesterday = date.today() - timedelta(days=1)
        active, ignored = ex.apply_exemptions(
            [_vuln("CVE-A")],
            [ex.ExemptVuln(id="CVE-A", reason="r", ignore_until=yesterday.isoformat())],
        )
        assert [v.cve_id for v in active] == ["CVE-A"]
        assert ignored == []

    def test_alias_match(self):
        vuln = _vuln(cve="GHSA-aaaa-bbbb-cccc", aliases=["CVE-2024-1111"])
        active, ignored = ex.apply_exemptions(
            [vuln], [ex.ExemptVuln(id="CVE-2024-1111", reason="r")]
        )
        assert active == []
        assert ignored[0]["cve_id"].startswith("GHSA")
        assert ignored[0]["matched_via"] == "CVE-2024-1111"

    def test_no_exemptions_passthrough(self):
        vulns = [_vuln(), _vuln("CVE-2")]
        active, ignored = ex.apply_exemptions(vulns, [])
        assert len(active) == 2 and ignored == []


class TestAnalyzerIntegration:
    def test_assess_security_filters_with_db(self, tmp_path):
        """端到端：真 DB 写入漏洞 → 设置豁免 → assess_security 过滤。"""
        import dependency_analyzer as da

        analyzer = da.DependencyAnalyzer(db_path=str(tmp_path / "graph.db"))
        try:
            pkg = da.DependencyNode(
                name="requests", version="2.3.0", ecosystem="pypi"
            )
            analyzer.db.add_package(pkg)
            analyzer.db.add_vulnerability(_vuln("CVE-A"))
            analyzer.db.add_vulnerability(_vuln("CVE-B"))

            analyzer.exemptions = [ex.ExemptVuln(id="CVE-A", reason="测试豁免")]
            active = analyzer.assess_security()
            assert [v.cve_id for v in active] == ["CVE-B"]
            assert analyzer.ignored_vulnerabilities[0]["cve_id"] == "CVE-A"
        finally:
            analyzer.close()
