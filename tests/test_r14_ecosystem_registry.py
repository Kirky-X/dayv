#!/usr/bin/env python3
"""R14 生态注册表回归测试（调研报告建议 14 验收项）。

验收点：
- 生态元数据单点（OSV 映射 / 文件检测 / 脚本入口 / purl type）
- analyze --list-parsers 对 nuget 显示 not_implemented
- DAYV_INDEX_URL_<ECO> 环境变量覆盖 registry 基址
- 同生态 lockfile 优先于 manifest（R4 前置行为）
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

import ecosystem_registry as eco_reg
import dependency_analyzer


class TestRegistrySingleSource:
    def test_osv_map_matches_registry(self):
        assert dependency_analyzer.OSV_ECOSYSTEM_MAP["pypi"] == "PyPI"
        assert dependency_analyzer.OSV_ECOSYSTEM_MAP["nuget"] == "NuGet"
        assert len(dependency_analyzer.OSV_ECOSYSTEM_MAP) == 7

    def test_choices_come_from_registry(self):
        names = eco_reg.ecosystem_names()
        assert names[0] == "pypi" and "nuget" in names and len(names) == 7

    def test_script_for_unknown_eco(self):
        assert eco_reg.script_for("pypi") == "pypi.py"
        assert eco_reg.script_for("golang") is None

    def test_parser_status_nuget_not_implemented(self):
        status = {row["ecosystem"]: row["status"] for row in eco_reg.parser_status()}
        assert status["nuget"] == "not_implemented"
        assert status["maven"] == "not_implemented"
        assert status["pypi"] == "implemented"

    def test_env_override_index_url(self, monkeypatch):
        monkeypatch.setenv("DAYV_INDEX_URL_MAVEN", "https://maven.corp.internal")
        assert eco_reg.index_base_url("maven") == "https://maven.corp.internal"
        monkeypatch.delenv("DAYV_INDEX_URL_MAVEN")
        assert eco_reg.index_base_url("maven") == "https://repo1.maven.org/maven2"


class TestLockfileDetectionPreference:
    def test_detect_prefers_lockfile_over_manifest(self, tmp_path):
        (tmp_path / "package.json").write_text('{"name": "demo"}', encoding="utf-8")
        (tmp_path / "package-lock.json").write_text("{}", encoding="utf-8")
        picked = dependency_analyzer.detect_dependency_file(str(tmp_path))
        assert picked == str(tmp_path / "package-lock.json")

    def test_detect_manifest_when_no_lockfile(self, tmp_path):
        (tmp_path / "package.json").write_text('{"name": "demo"}', encoding="utf-8")
        picked = dependency_analyzer.detect_dependency_file(str(tmp_path))
        assert picked == str(tmp_path / "package.json")

    def test_file_entry_kinds(self):
        assert eco_reg.file_entry("Cargo.lock")["kind"] == "lockfile"
        assert eco_reg.file_entry("Cargo.lock")["ecosystem"] == "crates"
        assert eco_reg.file_entry("go.mod") is None
