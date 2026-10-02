#!/usr/bin/env python3
"""R3 CI 退出码契约回归测试（调研报告建议 3 验收项）。

契约（参照 osv-scanner 0/1/127/128）：
- 0   = 成功（含未发现漏洞）
- N   = --exit-code N 且发现漏洞
- 128 = 输入/解析失败（manifest/lockfile/deps_data 缺失或非法）

用 mock Analyzer 离线驱动 cmd_analyze_data / cmd_security，不依赖网络。
"""

import argparse
import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

import dependency_analyzer as da
from dependency_analyzer import SecurityVulnerability, SeverityLevel


class FakeAnalyzer:
    """离线替身：assess_security 返回可配置漏洞集。"""

    vulns: list = []
    ignored_vulnerabilities: list = []
    osv_scan_status = {"scanned": True, "found": 0}

    def build_dependency_graph(self, packages, edges):
        pass

    def detect_conflicts(self):
        return []

    def recommend_optimal_versions(self):
        return {}

    def assess_security(self):
        return list(self.vulns)

    def plan_update_paths(self):
        return []

    def generate_report(self, root_package):
        return da.AnalysisReport(
            timestamp=0.0,
            root_package=root_package,
            total_packages=1,
            total_edges=0,
            conflicts=[],
            vulnerabilities=list(self.vulns),
            update_paths=[],
            recommendations=[],
            graph_stats={},
        )

    def export_report_json(self, report, output_file):
        Path(output_file).write_text("{}", encoding="utf-8")

    def close(self):
        pass


def _vuln():
    return SecurityVulnerability(
        package="requests",
        version="2.3.0",
        severity=SeverityLevel.HIGH,
        cve_id="CVE-2024-35195",
        description="mock",
    )


def _deps_file(tmp_path, payload=None):
    data = payload or {
        "packages": [{"name": "requests", "version": "2.3.0", "ecosystem": "pypi"}],
        "edges": [],
    }
    f = tmp_path / "deps_data.json"
    f.write_text(json.dumps(data), encoding="utf-8")
    return str(f)


def _args(tmp_path, **over):
    base = dict(
        data_file=_deps_file(tmp_path),
        conflicts=False,
        recommend=False,
        security=True,
        updates=False,
        report=False,
        output=None,
        exit_code=0,
    )
    base.update(over)
    return argparse.Namespace(**base)


@pytest.fixture()
def fake(monkeypatch):
    FakeAnalyzer.vulns = [_vuln()]
    monkeypatch.setattr(da, "DependencyAnalyzer", FakeAnalyzer)
    return FakeAnalyzer


class TestAnalyzeDataExitCode:
    def test_vulns_with_exit_code_1(self, tmp_path, fake):
        with pytest.raises(SystemExit) as exc:
            da.cmd_analyze_data(_args(tmp_path, exit_code=1))
        assert exc.value.code == 1

    def test_vulns_custom_code_2(self, tmp_path, fake):
        with pytest.raises(SystemExit) as exc:
            da.cmd_analyze_data(_args(tmp_path, exit_code=2))
        assert exc.value.code == 2

    def test_vulns_without_flag_exits_0(self, tmp_path, fake):
        da.cmd_analyze_data(_args(tmp_path))  # 不抛 SystemExit

    def test_no_vulns_exit_0_even_with_flag(self, tmp_path, fake):
        fake.vulns = []
        da.cmd_analyze_data(_args(tmp_path, exit_code=1))

    def test_report_branch_counts_vulns(self, tmp_path, fake):
        with pytest.raises(SystemExit) as exc:
            da.cmd_analyze_data(
                _args(tmp_path, security=False, report=True, exit_code=1)
            )
        assert exc.value.code == 1


class TestSecurityExitCode:
    @staticmethod
    def _patch_registry(monkeypatch, payload):
        """cmd_security 查最新版走 subprocess 调生态脚本——离线替身。"""
        import subprocess

        class FakeProcResult:
            returncode = 0
            stdout = json.dumps(payload)
            stderr = ""

        monkeypatch.setattr(subprocess, "run", lambda *a, **k: FakeProcResult())

    def test_exit_1_with_vulns(self, tmp_path, fake, monkeypatch):
        self._patch_registry(monkeypatch, {"latest_version": "2.31.0"})
        args = argparse.Namespace(
            package="requests", ecosystem="pypi", priority=False, exit_code=1
        )
        with pytest.raises(SystemExit) as exc:
            da.cmd_security(args)
        assert exc.value.code == 1

    def test_exit_0_without_flag(self, tmp_path, fake, monkeypatch):
        self._patch_registry(monkeypatch, {"latest_version": "2.31.0"})
        args = argparse.Namespace(
            package="requests", ecosystem="pypi", priority=False, exit_code=0
        )
        da.cmd_security(args)  # 不抛 SystemExit


class TestInputError128:
    def test_missing_deps_data_is_128(self, tmp_path):
        args = _args(tmp_path)
        args.data_file = str(tmp_path / "nope.json")
        with pytest.raises(SystemExit) as exc:
            da.cmd_analyze_data(args)
        assert exc.value.code == 128

    def test_invalid_json_is_128(self, tmp_path):
        f = tmp_path / "bad.json"
        f.write_text("{not json", encoding="utf-8")
        args = _args(tmp_path)
        args.data_file = str(f)
        with pytest.raises(SystemExit) as exc:
            da.cmd_analyze_data(args)
        assert exc.value.code == 128

    def test_missing_schema_is_128(self, tmp_path):
        f = tmp_path / "noschema.json"
        f.write_text(json.dumps({"foo": 1}), encoding="utf-8")
        args = _args(tmp_path)
        args.data_file = str(f)
        with pytest.raises(SystemExit) as exc:
            da.cmd_analyze_data(args)
        assert exc.value.code == 128
