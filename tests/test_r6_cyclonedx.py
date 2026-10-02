#!/usr/bin/env python3
"""R6 CycloneDX 输出 + SBOM 反向输入回归测试（调研报告建议 6 验收项）。

验收点：
- dayv 生成 cdx JSON（bomFormat/specVersion/components[].purl/dependencies[]）
- _sbom_to_deps_data 消费 dayv 自产 SPDX 与外部 CycloneDX 样例
- analyze-data --from-sbom 全链路（FakeAnalyzer 离线驱动）
"""

import argparse
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

import sbom_generator
import dependency_analyzer as da


SAMPLE = [
    {"name": "demo", "version": "1.0.0", "ecosystem": "npm", "is_root": True},
    {"name": "express", "version": "4.18.2", "ecosystem": "npm", "license": "MIT"},
    {"name": "accepts", "version": "1.3.8", "ecosystem": "npm"},
]
EDGES = [
    {"source": "demo", "target": "express", "constraint": "^4.18.0"},
    {"source": "express", "target": "accepts", "constraint": "~1.3.8"},
]


class TestCycloneDXWriter:
    def test_structure(self):
        cdx = sbom_generator.generate_cyclonedx(SAMPLE, EDGES, "demo")
        assert cdx["bomFormat"] == "CycloneDX"
        assert cdx["specVersion"] == "1.5"
        root = cdx["metadata"]["component"]
        assert root["name"] == "demo" and root["type"] == "application"
        names = {c["name"] for c in cdx["components"]}
        assert names == {"express", "accepts"}
        express = [c for c in cdx["components"] if c["name"] == "express"][0]
        assert express["purl"] == "pkg:npm/express@4.18.2"
        assert express["licenses"][0]["license"]["id"] == "MIT"

    def test_dependencies_depends_on(self):
        cdx = sbom_generator.generate_cyclonedx(SAMPLE, EDGES, "demo")
        deps = {d["ref"]: d["dependsOn"] for d in cdx["dependencies"]}
        root_ref = cdx["metadata"]["component"]["bom-ref"]
        express_ref = [
            c["bom-ref"] for c in cdx["components"] if c["name"] == "express"
        ][0]
        assert express_ref in deps[root_ref]
        accepts_ref = [
            c["bom-ref"] for c in cdx["components"] if c["name"] == "accepts"
        ][0]
        assert accepts_ref in deps[express_ref]

    def test_write_cyclonedx(self, tmp_path):
        out = tmp_path / "demo-sbom.cdx.json"
        got = sbom_generator.write_cyclonedx(SAMPLE, EDGES, "demo", str(out))
        assert got == str(out)
        data = json.loads(out.read_text(encoding="utf-8"))
        assert data["bomFormat"] == "CycloneDX"

    def test_cmd_report_cyclonedx_format(self, tmp_path):
        deps_file = tmp_path / "deps_data.json"
        deps_file.write_text(
            json.dumps({"packages": SAMPLE, "edges": EDGES}), encoding="utf-8"
        )
        out = tmp_path / "out.cdx.json"
        args = argparse.Namespace(
            data_file=str(deps_file), format="cyclonedx", output=str(out),
            allowed_licenses=None, license_categories=None,
        )
        da.cmd_report(args)
        assert out.is_file()
        assert json.loads(out.read_text(encoding="utf-8"))["bomFormat"] == "CycloneDX"


class TestSbomReverseInput:
    def test_own_spdx_roundtrip(self, tmp_path):
        spdx_file = tmp_path / "demo.spdx.json"
        sbom_generator.write_sbom(
            [dict(p) for p in SAMPLE], EDGES, "demo", str(spdx_file)
        )
        data = da._sbom_to_deps_data(spdx_file)
        by_name = {p["name"]: p for p in data["packages"]}
        assert by_name["demo"]["is_root"] is True
        assert by_name["express"]["ecosystem"] == "npm"
        assert by_name["express"]["version_resolved"] is True
        assert by_name["accepts"]["license"] == ""  # NOASSERTION 归一为空串
        pairs = {(e["source"], e["target"]) for e in data["edges"]}
        assert ("demo", "express") in pairs and ("express", "accepts") in pairs

    def test_external_cyclonedx_sample(self, tmp_path):
        cdx = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "metadata": {
                "component": {
                    "type": "application",
                    "bom-ref": "root-1",
                    "name": "syft-out",
                    "version": "2.0.0",
                }
            },
            "components": [
                {
                    "type": "library",
                    "bom-ref": "c1",
                    "name": "lodash",
                    "version": "4.17.21",
                    "purl": "pkg:npm/lodash@4.17.21",
                    "licenses": [{"license": {"id": "MIT"}}],
                }
            ],
            "dependencies": [
                {"ref": "root-1", "dependsOn": ["c1"]},
                {"ref": "c1", "dependsOn": []},
            ],
        }
        f = tmp_path / "sbom.cdx.json"
        f.write_text(json.dumps(cdx), encoding="utf-8")
        data = da._sbom_to_deps_data(f)
        assert data["packages"][0]["name"] == "syft-out"
        assert data["packages"][0]["is_root"] is True
        lodash = [p for p in data["packages"] if p["name"] == "lodash"][0]
        assert lodash["ecosystem"] == "npm"  # 由 purl 反推
        assert lodash["license"] == "MIT"
        assert data["edges"] == [{"source": "syft-out", "target": "lodash",
                                  "constraint": "*"}]

    def test_unknown_format_exits_128(self, tmp_path):
        f = tmp_path / "x.json"
        f.write_text(json.dumps({"foo": 1}), encoding="utf-8")
        with pytest.raises(SystemExit) as exc:
            da._sbom_to_deps_data(f)
        assert exc.value.code == 128


class TestAnalyzeDataFromSbom:
    def test_from_sbom_end_to_end(self, tmp_path, monkeypatch):
        captured = {}

        class FakeAnalyzer:
            def __init__(self, *a, **k):
                pass

            def build_dependency_graph(self, packages, edges):
                captured["packages"] = packages
                captured["edges"] = edges

            def detect_conflicts(self):
                return []

            def recommend_optimal_versions(self):
                return {}

            def assess_security(self):
                return []

            ignored_vulnerabilities: list = []

            def plan_update_paths(self):
                return []

            def close(self):
                pass

        monkeypatch.setattr(da, "DependencyAnalyzer", FakeAnalyzer)

        spdx_file = tmp_path / "demo.spdx.json"
        sbom_generator.write_sbom([dict(p) for p in SAMPLE], EDGES, "demo", str(spdx_file))

        args = argparse.Namespace(
            data_file=None,
            from_sbom=str(spdx_file),
            conflicts=False,
            recommend=False,
            security=False,
            updates=False,
            report=False,
            output=None,
            exit_code=0,
            config=None,
            cache=False,
        )
        da.cmd_analyze_data(args)
        names = {p.name for p in captured["packages"]}
        assert "express" in names and "demo" in names

    def test_missing_both_inputs_is_128(self, tmp_path):
        args = argparse.Namespace(
            data_file=None, from_sbom=None, exit_code=0,
        )
        with pytest.raises(SystemExit) as exc:
            da.cmd_analyze_data(args)
        assert exc.value.code == 128
