#!/usr/bin/env python3
"""R10 deps.dev 集成回归测试（调研报告建议 10 验收项）。

验收点：
- Cargo.toml 样例项目 analyze 不再 exit 1（最小解析离线可用）
- deps.dev 不可达时自动降级现有路径并在 manifest_notes（→scan_warnings）标注
- GetDependencies 响应归一（nodes/edges 索引引用 → name@version）
- 生态覆盖错位：packagist/rubygems/nuget 不调 GetDependencies
- security findings 增强信号 / health --scorecard 失败不阻断
"""

import argparse
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

import dependency_analyzer as da
import depsdev_client
from dependency_analyzer import DependencyAnalyzer, DependencyNode

CARGO_TOML = """\
[package]
name = "demo-rs"
version = "0.1.0"
edition = "2021"

[dependencies]
serde = "1.0"
rand = { version = "0.8" }
"""


class TestCargoMinimalParse:
    def test_cargo_toml_parses_offline(self, tmp_path, monkeypatch):
        (tmp_path / "Cargo.toml").write_text(CARGO_TOML, encoding="utf-8")

        def fail_get(url):
            raise RuntimeError("offline")

        monkeypatch.setattr(depsdev_client, "_default_get_json", fail_get)
        # deps.dev 不可达（离线注入失败）也必须成功返回直接依赖
        packages, edges, eco = da.parse_dependencies(str(tmp_path))
        assert eco == "crates"
        names = {p.name for p in packages}
        assert {"demo-rs", "serde", "rand"} <= names
        # Cargo "1.0" 是范围约束 → 下界 1.0 + version_inferred
        serde = [p for p in packages if p.name == "serde"][0]
        assert serde.version == "1.0" and serde.version_inferred is True

    def test_depsdev_unreachable_degrades_with_note(self, tmp_path, monkeypatch):
        (tmp_path / "Cargo.toml").write_text(CARGO_TOML, encoding="utf-8")

        def fail_get(url):
            raise RuntimeError("network unreachable")

        monkeypatch.setattr(depsdev_client, "_default_get_json", fail_get)
        packages, edges, eco = da.parse_dependencies(str(tmp_path))
        root = packages[0]
        assert root.is_root and root.name == "demo-rs"
        notes = "\n".join(root.properties.get("manifest_notes", []))
        assert "deps.dev" in notes and "仅含直接依赖" in notes

    def test_depsdev_enrich_adds_transitive(self, tmp_path, monkeypatch):
        (tmp_path / "Cargo.toml").write_text(CARGO_TOML, encoding="utf-8")
        payload = {
            "nodes": [
                {"versionKey": {"system": "CARGO", "name": "demo-rs", "version": "0.1.0"}},
                {"versionKey": {"system": "CARGO", "name": "serde", "version": "1.0.193"}},
                {"versionKey": {"system": "CARGO", "name": "serde_derive", "version": "1.0.193"}},
            ],
            "edges": [
                {"fromNode": 0, "toNode": 1, "requirement": "1.0"},
                {"fromNode": 1, "toNode": 2, "requirement": "1.0"},
            ],
        }
        monkeypatch.setattr(
            depsdev_client, "_default_get_json", lambda url: payload
        )
        packages, edges, eco = da.parse_dependencies(str(tmp_path))
        names = {p.name for p in packages}
        assert "serde_derive" in names  # 传递依赖经服务端解析补入
        transitive = [p for p in packages if p.name == "serde_derive"][0]
        assert transitive.version_resolved is True
        pairs = {(e.source, e.target) for e in edges}
        assert ("serde", "serde_derive") in pairs


class TestClient:
    def test_ecosystem_coverage_guard(self, monkeypatch):
        # GetDependencies 生态错位：packagist/rubygems/nuget 不发请求
        def fail(url):
            raise AssertionError("不该发请求")

        assert depsdev_client.get_dependencies("packagist", "vendor/pkg", "1.0.0", fail) is None
        assert depsdev_client.get_dependencies("rubygems", "rails", "7.0.4", fail) is None
        assert depsdev_client.get_dependencies("nuget", "Newtonsoft.Json", "13.0.3", fail) is None

    def test_normalize_payload(self):
        payload = {
            "nodes": [
                {"versionKey": {"system": "NPM", "name": "express", "version": "4.21.2"}},
                {"versionKey": {"system": "NPM", "name": "accepts", "version": "1.3.8"}},
            ],
            "edges": [{"fromNode": 0, "toNode": 1, "requirement": "~1.3.8"}],
        }
        nodes, edges = depsdev_client.normalize_dependencies_payload(payload, "npm")
        assert nodes[0] == {"name": "express", "version": "4.21.2", "ecosystem": "npm"}
        assert edges == [
            {"source": "express@4.21.2", "target": "accepts@1.3.8", "constraint": "~1.3.8"}
        ]

    def test_failure_returns_none_not_raise(self, monkeypatch):
        def fail(url):
            raise RuntimeError("down")

        assert depsdev_client.get_dependencies("npm", "express", "4.21.2", fail) is None
        assert depsdev_client.get_findings("npm", "express", "4.21.2", fail) is None
        assert depsdev_client.get_scorecard("npm", "express", "4.21.2", fail) is None
        assert depsdev_client.get_requirements("pypi", "requests", "2.31.0", fail) is None
        assert depsdev_client.purl_lookup("pkg:npm/express@4.21.2", fail) is None


class TestSecurityFindings:
    def test_findings_printed(self, tmp_path, monkeypatch, capsys):
        class FakeProcResult:
            returncode = 0
            stdout = json.dumps({"latest_version": "2.31.0"})
            stderr = ""

        import subprocess

        monkeypatch.setattr(subprocess, "run", lambda *a, **k: FakeProcResult())

        class FakeAnalyzer:
            osv_scan_status = {"scanned": True}
            ignored_vulnerabilities: list = []

            def __init__(self, *a, **k):
                pass

            def build_dependency_graph(self, p, e):
                pass

            def assess_security(self):
                return []

            def close(self):
                pass

        monkeypatch.setattr(da, "DependencyAnalyzer", FakeAnalyzer)
        monkeypatch.setattr(
            depsdev_client,
            "get_findings",
            lambda eco, name, ver, http_get=None: [
                {"finding_type": "DEPRECATED"},
                {
                    "finding_type": "REMEDIATION",
                    "remediation": {"recommended_versions": ["2.32.0"]},
                },
            ],
        )
        args = argparse.Namespace(
            package="requests", ecosystem="pypi", priority=False,
            exit_code=0, config=None, offline=False, download_offline_db=False,
            cache=False,
        )
        da.cmd_security(args)
        out = capsys.readouterr().out
        assert "DEPRECATED" in out
        assert "REMEDIATION" in out and "2.32.0" in out

    def test_findings_failure_silent(self, tmp_path, monkeypatch, capsys):
        class FakeProcResult:
            returncode = 0
            stdout = json.dumps({"latest_version": "2.31.0"})
            stderr = ""

        import subprocess

        monkeypatch.setattr(subprocess, "run", lambda *a, **k: FakeProcResult())

        class FakeAnalyzer:
            osv_scan_status = {"scanned": True}
            ignored_vulnerabilities: list = []

            def __init__(self, *a, **k):
                pass

            def build_dependency_graph(self, p, e):
                pass

            def assess_security(self):
                return []

            def close(self):
                pass

        monkeypatch.setattr(da, "DependencyAnalyzer", FakeAnalyzer)

        def boom(*a, **k):
            raise RuntimeError("down")

        monkeypatch.setattr(depsdev_client, "get_findings", boom)
        args = argparse.Namespace(
            package="requests", ecosystem="pypi", priority=False,
            exit_code=0, config=None, offline=False, download_offline_db=False,
            cache=False,
        )
        da.cmd_security(args)  # 不抛异常
        assert "deps.dev findings" not in capsys.readouterr().out
