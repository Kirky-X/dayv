#!/usr/bin/env python3
"""G3 回归测试：伪版本号不得送进 OSV 查询。

修复前:
- parse_package_json 用 lstrip("^~>=<") 截断约束，"1.2.x" 等伪版本直接当
  真实版本送 OSV；无法解析时缺省编造 "0.0.0"。
- parse_pyproject_toml / parse_requirements_txt 对 ^ / ~ / 裸包名缺省填 "0.0.0"。
- OSV 跳过只在日志出现，报告不显式记录跳过数量与原因。

修复后:
- 可解析出确定版本的取下界并标记 version_inferred（^1.2.0 → 1.2.0, True）。
- 无法得到确定版本的包 version 为空串，OSV 查询跳过，且跳过数量与包名
  显式出现在报告 scan_warnings 中。
"""
import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

import dependency_analyzer as da
from _mocks import CapturingHttpClient, NullLicenseFetcher


def write_package_json(payload: dict) -> str:
    fd, path = tempfile.mkstemp(suffix="package.json")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(payload, f)
    return path


class TestExtractConcreteVersion(unittest.TestCase):
    """表驱动：版本约束 → 确定版本（下界）与 inferred 标记。"""

    def test_caret_constraint_resolves_to_lower_bound_marked_inferred(self):
        self.assertEqual(
            da._extract_concrete_version("^1.2.0"),
            ("1.2.0", True),
            "^1.2.0 应解析为下界 1.2.0 且标记 inferred",
        )

    def test_range_operators_are_inferred_lower_bounds(self):
        for constraint, expected in [
            ("~1.2.3", ("1.2.3", True)),
            (">=2.0.0", ("2.0.0", True)),
            ("~=1.2.3", ("1.2.3", True)),
            (">=2.0,<3.0", ("2.0", True)),
            ("1.2.0 - 2.0.0", ("1.2.0", True)),
        ]:
            self.assertEqual(da._extract_concrete_version(constraint), expected)

    def test_exact_versions_are_not_inferred(self):
        self.assertEqual(da._extract_concrete_version("1.2.3"), ("1.2.3", False))
        self.assertEqual(da._extract_concrete_version("==3.4.5"), ("3.4.5", False))

    def test_unresolvable_constraints_return_none(self):
        # 通配 / 标签 / 链接 / 排除式 / 纯上界 / OR 复合：无确定版本
        for constraint in [
            "*",
            "latest",
            "1.2.x",
            "1.x",
            "workspace:*",
            "file:../pkg",
            "git+https://github.com/a/b",
            "<2.0.0",
            "<=1.9.0",
            "!=1.2.3",
            ">1.0.0",
            "^1.2 || ^3",
            "",
        ]:
            self.assertIsNone(
                da._extract_concrete_version(constraint),
                f"约束 {constraint!r} 无确定版本，必须返回 None",
            )


class TestParsersProduceNoFakeVersions(unittest.TestCase):
    """三个解析器都不得产出编造版本（0.0.0 / 伪版本）。"""

    def test_parse_package_json_resolves_and_marks_inferred(self):
        path = write_package_json(
            {
                "name": "demo",
                "version": "1.0.0",
                "dependencies": {
                    "lodash": "^4.17.21",
                    "left-pad": "*",
                    "chalk": "latest",
                    "ansi-styles": "4.3.x",
                },
            }
        )
        try:
            packages, _ = da.parse_package_json(path)
        finally:
            os.remove(path)

        by_name = {p.name: p for p in packages if not p.is_root}
        lodash = by_name["lodash"]
        self.assertEqual(lodash.version, "4.17.21", "^4.17.21 应取下界 4.17.21")
        self.assertTrue(lodash.version_inferred, "范围约束下界应标记 inferred")
        for name in ("left-pad", "chalk", "ansi-styles"):
            self.assertEqual(
                by_name[name].version, "", f"{name} 无确定版本时应留空"
            )
            self.assertFalse(by_name[name].version_inferred)
        self.assertFalse(
            any(p.version == "0.0.0" for p in packages),
            "修复后任何包都不得再携带编造的 0.0.0 版本",
        )

    def test_parse_pyproject_toml_handles_caret_and_bare_names(self):
        fd, path = tempfile.mkstemp(suffix=".toml")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(
                '[project]\n'
                'name = "demo"\n'
                'version = "0.1.0"\n'
                'dependencies = [\n'
                '  "requests>=2.28.0",\n'
                '  "flask~=3.0.1",\n'
                '  "six",\n'
                ']\n'
            )
        try:
            packages, _ = da.parse_pyproject_toml(path)
        finally:
            os.remove(path)

        by_name = {p.name: p for p in packages if not p.is_root}
        self.assertEqual(by_name["requests"].version, "2.28.0")
        self.assertTrue(by_name["requests"].version_inferred)
        self.assertEqual(by_name["flask"].version, "3.0.1")
        self.assertEqual(
            by_name["six"].version, "", "裸包名无确定版本应留空而非 0.0.0"
        )
        self.assertFalse(any(p.version == "0.0.0" for p in packages))

    def test_parse_requirements_txt_compound_constraint_takes_first_lower_bound(self):
        fd, path = tempfile.mkstemp(suffix=".txt")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write("requests>=2.0,<3.0\nsix\n")
        try:
            packages, _ = da.parse_requirements_txt(path)
        finally:
            os.remove(path)

        by_name = {p.name: p for p in packages}
        self.assertEqual(by_name["requests"].version, "2.0")
        self.assertTrue(by_name["requests"].version_inferred)
        self.assertEqual(by_name["six"].version, "")
        self.assertFalse(any(p.version == "0.0.0" for p in packages))


class TestOsvQueryUsesResolvedVersions(unittest.TestCase):
    """OSV 查询行为：下界真实提交、无版本包跳过且显式报告。"""

    def _build(self, dependencies: dict):
        path = write_package_json(
            {"name": "demo", "version": "1.0.0", "dependencies": dependencies}
        )
        try:
            packages, edges = da.parse_package_json(path)
        finally:
            os.remove(path)
        http = CapturingHttpClient()
        analyzer = da.DependencyAnalyzer(
            http_client=http, license_fetcher=NullLicenseFetcher()
        )
        analyzer.build_dependency_graph(packages, edges)
        # 注意：不在此处 close，调用方在用完 generate_report 后自行关闭
        return analyzer, http

    def test_inferred_lower_bound_is_actually_sent_to_osv(self):
        _, http = self._build({"lodash": "^4.17.21"})
        sent_versions = [
            q["version"] for call in http.calls for q in call["queries"]
        ]
        self.assertIn(
            "4.17.21",
            sent_versions,
            "OSV 查询应使用 ^4.17.21 的下界 4.17.21",
        )
        self.assertNotIn(
            "0.0.0", sent_versions, "伪版本 0.0.0 不得进入 OSV 查询"
        )

    def test_unresolvable_versions_skipped_and_reported_in_scan_warnings(self):
        analyzer, http = self._build({"left-pad": "*", "lodash": "^4.17.21"})
        # 无确定版本的包根本不应产生 OSV 查询
        sent_names = [
            q["package"]["name"] for call in http.calls for q in call["queries"]
        ]
        self.assertNotIn("left-pad", sent_names, "* 通配包应跳过 OSV 查询")
        self.assertIn("lodash", sent_names)

        # 跳过必须显式出现在报告输出（规则11：跳过禁止埋在日志里）
        try:
            report = analyzer.generate_report("demo")
            report_dict = analyzer.report_to_dict(report)
        finally:
            analyzer.close()
        warnings_text = "\n".join(report_dict["scan_warnings"])
        self.assertIn(
            "跳过 1 个", warnings_text, "scan_warnings 应显式报告跳过数量"
        )
        self.assertIn("left-pad", warnings_text, "scan_warnings 应列出被跳过的包名")

    def test_inferred_count_reported_in_scan_warnings(self):
        analyzer, _ = self._build({"lodash": "^4.17.21"})
        try:
            report = analyzer.generate_report("demo")
            report_dict = analyzer.report_to_dict(report)
        finally:
            analyzer.close()
        warnings_text = "\n".join(report_dict["scan_warnings"])
        self.assertIn(
            "推断的下界版本",
            warnings_text,
            "使用推断下界提交 OSV 时应在报告中显式声明保守近似",
        )


class TestBuildOsvQueriesSkipsEmptyVersions(unittest.TestCase):
    """_build_osv_queries：空版本包进入 skipped 并说明原因。"""

    def test_empty_version_package_is_skipped_with_reason(self):
        packages = [
            da.DependencyNode(name="root", version="1.0.0", ecosystem="npm", is_root=True),
            da.DependencyNode(name="mystery", version="", ecosystem="npm"),
        ]
        queries, index, skipped = da._build_osv_queries(packages)
        self.assertEqual(len(queries), 1, "只有确定版本的包产生查询")
        self.assertEqual(index[0].name, "root")
        self.assertEqual(len(skipped), 1)
        self.assertIn("mystery", skipped[0])
        self.assertIn("无", skipped[0], "跳过描述应包含原因")


if __name__ == "__main__":
    unittest.main()
