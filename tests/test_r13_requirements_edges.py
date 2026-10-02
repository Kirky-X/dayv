#!/usr/bin/env python3
"""R13 requirements.txt 解析升级回归测试（调研报告建议 13 验收项）。

验收点：
- 含交叉版本约束的两文件 requirements 项目能检出冲突
- 单文件无约束项目报告含显性降级说明（manifest_notes → scan_warnings）
- 每条声明产 root→dep 约束边（冲突检测与 --impact 不再空转）
- -r 递归 / -c 约束 / marker 求值 / 精确 pin 标 version_resolved
"""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

import dependency_analyzer as da
from dependency_analyzer import DependencyAnalyzer


def _write(tmp_path, name, content):
    f = tmp_path / name
    f.write_text(content, encoding="utf-8")
    return f


class TestEdgesProduced:
    def test_basic_edges_and_root(self, tmp_path):
        _write(
            tmp_path,
            "requirements.txt",
            "requests>=2.28\nflask==2.3.2\n",
        )
        packages, edges = da.parse_requirements_txt(str(tmp_path / "requirements.txt"))
        root = [p for p in packages if p.is_root]
        assert root and root[0].name == tmp_path.name
        pairs = {(e.source, e.target, e.constraint) for e in edges}
        assert (root[0].name, "requests", ">=2.28") in pairs
        assert (root[0].name, "flask", "==2.3.2") in pairs

    def test_exact_pin_marks_resolved(self, tmp_path):
        _write(tmp_path, "requirements.txt", "flask==2.3.2\nrequests>=2.28\n")
        packages, _ = da.parse_requirements_txt(str(tmp_path / "requirements.txt"))
        by_name = {p.name: p for p in packages}
        assert by_name["flask"].version_resolved is True
        assert by_name["flask"].version_inferred is False
        assert by_name["requests"].version_resolved is False
        assert by_name["requests"].version_inferred is True

    def test_root_name_from_pyproject(self, tmp_path):
        _write(tmp_path, "requirements.txt", "requests\n")
        _write(
            tmp_path,
            "pyproject.toml",
            '[project]\nname = "my-app"\nversion = "1.2.3"\n',
        )
        packages, _ = da.parse_requirements_txt(str(tmp_path / "requirements.txt"))
        assert packages[0].name == "my-app"


class TestMultiFileConflicts:
    def test_cross_constraint_conflict_detected(self, tmp_path):
        _write(tmp_path, "requirements.txt", "-r base.txt\ncommon==2.0\n")
        _write(tmp_path, "base.txt", "common==1.0\nsix\n")
        packages, edges = da.parse_requirements_txt(str(tmp_path / "requirements.txt"))
        constraints = [e.constraint for e in edges if e.target == "common"]
        assert set(constraints) == {"==1.0", "==2.0"}

        # 全链路：建图后 detect_conflicts 检出该冲突
        analyzer = DependencyAnalyzer(db_path=str(tmp_path / "g.db"))
        try:
            analyzer.build_dependency_graph(packages, edges)
            conflicts = analyzer.detect_conflicts()
            assert any(c.package == "common" for c in conflicts)
        finally:
            analyzer.close()

    def test_constraint_file_applies_to_declared(self, tmp_path):
        _write(
            tmp_path,
            "requirements.txt",
            "-c constraints.txt\nrequests>=2.0\n",
        )
        _write(tmp_path, "constraints.txt", "requests<3.0\n")
        packages, edges = da.parse_requirements_txt(str(tmp_path / "requirements.txt"))
        constraints = [e.constraint for e in edges if e.target == "requests"]
        assert set(constraints) == {">=2.0", "<3.0"}


class TestMarkersAndOptions:
    def test_marker_extra_skips(self, tmp_path, caplog):
        _write(
            tmp_path,
            "requirements.txt",
            'requests\nuvicorn[standard]; extra == "web"\n',
        )
        packages, _ = da.parse_requirements_txt(str(tmp_path / "requirements.txt"))
        names = {p.name for p in packages}
        assert "requests" in names
        assert "uvicorn" not in names  # 顶层安装 extra 未激活

    def test_marker_python_version_included(self, tmp_path):
        _write(
            tmp_path,
            "requirements.txt",
            'numpy; python_version >= "3.8"\n',
        )
        packages, _ = da.parse_requirements_txt(str(tmp_path / "requirements.txt"))
        assert any(p.name == "numpy" for p in packages)

    def test_unknown_marker_conservative_include(self, tmp_path):
        _write(
            tmp_path,
            "requirements.txt",
            'weirdpkg; os_name == "plan9"\n',
        )
        packages, _ = da.parse_requirements_txt(str(tmp_path / "requirements.txt"))
        assert any(p.name == "weirdpkg" for p in packages)

    def test_pip_options_skipped(self, tmp_path):
        _write(
            tmp_path,
            "requirements.txt",
            "--index-url https://example.com/simple\nrequests\n",
        )
        packages, _ = da.parse_requirements_txt(str(tmp_path / "requirements.txt"))
        assert any(p.name == "requests" for p in packages)


class TestExplicitDegradation:
    def test_manifest_notes_attached_to_root(self, tmp_path):
        _write(tmp_path, "requirements.txt", "requests\n")
        packages, _ = da.parse_requirements_txt(str(tmp_path / "requirements.txt"))
        root = packages[0]
        assert root.is_root
        assert any("不含传递依赖关系" in n for n in root.properties["manifest_notes"])

    def test_notes_reach_scan_warnings(self, tmp_path):
        _write(tmp_path, "requirements.txt", "requests==2.31.0\n")
        packages, edges = da.parse_requirements_txt(str(tmp_path / "requirements.txt"))
        analyzer = DependencyAnalyzer(
            db_path=str(tmp_path / "g.db"),
            http_client=_NoHTTP(),
            offline_db=True,
            osv_db_dir=str(tmp_path / "none"),
            cache_ttl=None,
        )
        try:
            analyzer.build_dependency_graph(packages, edges)
            report = analyzer.generate_report(packages[0].name)
            assert any("不含传递依赖关系" in w for w in report.scan_warnings)
        finally:
            analyzer.close()

    def test_duplicate_declaration_multi_constraint(self, tmp_path):
        _write(tmp_path, "requirements.txt", "common==1.0\ncommon==2.0\n")
        packages, edges = da.parse_requirements_txt(str(tmp_path / "requirements.txt"))
        # 节点去重（Package 主键），约束边逐条保留
        assert len([p for p in packages if p.name == "common"]) == 1
        assert len([e for e in edges if e.target == "common"]) == 2


class _NoHTTP:
    def post(self, *a, **k):
        raise AssertionError("测试不应发网络请求")
