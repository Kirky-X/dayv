#!/usr/bin/env python3
"""G4 回归测试：规则16 架构/性能审查修复项。

1. [HIGH] license 单一数据源 = 图 DB：enrich_licenses 回写 Package.license，
   _collect_license_info 从 DB 读，DB 中永远查得到采集结果。
2. [MEDIUM] OSV 扫描跳过按原因分桶：生态未映射 ≠ 无确定版本，scan_warnings
   分别报告，不再统一写成"无确定版本"。
3. [MEDIUM] 外部 deps_data 入口（analyze-data / report）对 version 归一化：
   伪版本（1.2.x / * / latest）置空，范围串取下界标 version_inferred。
4. [MEDIUM-性能] enrich_licenses 移除串行回退：fetch_many 异常时全员 UNKNOWN，
   不得逐包重试 fetch。
5. [MEDIUM-性能] ecosystem 脚本 --batch 批量协议：fetch_many 每生态一次子进程，
   整批失败回退逐包路径；readme 许可证列优先取 deps_data（DB 单一数据源）。
"""
import io
import json
import os
import sys
import unittest
from contextlib import redirect_stdout
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

import base_ecosystem
import dependency_analyzer as da
import readme_generator
from _mocks import (
    CapturingHttpClient,
    FailingLicenseFetcher,
    MapLicenseFetcher,
)


def make_analyzer(license_map=None, fetcher=None):
    return da.DependencyAnalyzer(
        http_client=CapturingHttpClient(),
        license_fetcher=fetcher or MapLicenseFetcher(license_map or {}),
    )


def build_demo_graph(analyzer):
    packages = [
        da.DependencyNode(name="demo", version="1.0.0", ecosystem="npm", is_root=True),
        da.DependencyNode(name="lodash", version="4.17.21", ecosystem="npm"),
        da.DependencyNode(name="gplpkg", version="2.0.0", ecosystem="npm"),
    ]
    edges = [
        da.DependencyEdge(source="demo", target="lodash", constraint="^4.17.21"),
        da.DependencyEdge(source="demo", target="gplpkg", constraint="^2.0.0"),
    ]
    analyzer.build_dependency_graph(packages, edges)
    return packages


class TestLicenseSingleSourceIsGraphDB(unittest.TestCase):
    """license 单一存储点 = 图 DB Package.license。"""

    def test_enrich_writes_back_to_db(self):
        analyzer = make_analyzer({"lodash": "MIT", "gplpkg": "GPL-3.0"})
        try:
            packages = build_demo_graph(analyzer)
            da.enrich_licenses(packages, fetcher=analyzer._license_fetcher, db=analyzer.db)
            license_map = analyzer.db.get_license_map()
            self.assertEqual(
                license_map.get("lodash"), "MIT", "enrich 结果必须回写图 DB"
            )
            self.assertEqual(license_map.get("gplpkg"), "GPL-3.0")
        finally:
            analyzer.close()

    def test_collect_license_info_reads_from_db(self):
        analyzer = make_analyzer({"lodash": "MIT", "gplpkg": ""})
        try:
            build_demo_graph(analyzer)
            info = analyzer._collect_license_info()
            by_name = {e["package"]: e["license"] for e in info}
            self.assertEqual(by_name.get("lodash"), "MIT", "读到的必须是 DB 存储值")
            self.assertEqual(
                by_name.get("gplpkg"), "UNKNOWN", "DB 空串在报告层显式标 UNKNOWN"
            )
            # DB 中确实有采集结果（单一存储点落库证据）
            self.assertEqual(analyzer.db.get_license_map().get("lodash"), "MIT")

            # 二次调用不得重复 enrich（换故障 fetcher 后结果不变即守卫生效）
            analyzer._license_fetcher = FailingLicenseFetcher()
            info_again = analyzer._collect_license_info()
            self.assertEqual(info, info_again)
        finally:
            analyzer.close()

    def test_generate_report_license_comes_from_db(self):
        analyzer = make_analyzer({"lodash": "MIT", "gplpkg": "GPL-3.0"})
        try:
            build_demo_graph(analyzer)
            report = analyzer.generate_report("demo")
            report_dict = analyzer.report_to_dict(report)
        finally:
            analyzer.close()
        licenses = {e["package"]: e["license"] for e in report_dict["license_info"]}
        self.assertEqual(licenses.get("lodash"), "MIT")
        self.assertEqual(licenses.get("gplpkg"), "GPL-3.0")


class TestScanWarningsBucketedByReason(unittest.TestCase):
    """OSV 跳过原因分桶：生态未映射与无确定版本分别报告。"""

    def test_unmapped_ecosystem_and_no_version_reported_separately(self):
        analyzer = make_analyzer({})
        packages = [
            da.DependencyNode(name="demo", version="1.0.0", ecosystem="npm", is_root=True),
            da.DependencyNode(name="ok", version="1.0.0", ecosystem="npm"),
            da.DependencyNode(name="weird", version="1.0.0", ecosystem="unknown_eco"),
            da.DependencyNode(name="mystery", version="", ecosystem="npm"),
        ]
        edges = [
            da.DependencyEdge(source="demo", target="ok", constraint="*"),
            da.DependencyEdge(source="demo", target="weird", constraint="*"),
            da.DependencyEdge(source="demo", target="mystery", constraint="*"),
        ]
        try:
            analyzer.build_dependency_graph(packages, edges)
            report = analyzer.generate_report("demo")
            report_dict = analyzer.report_to_dict(report)
        finally:
            analyzer.close()

        warnings_text = "\n".join(report_dict["scan_warnings"])
        unmapped_warnings = [
            w for w in report_dict["scan_warnings"] if "生态系统未映射" in w
        ]
        no_version_warnings = [
            w for w in report_dict["scan_warnings"] if "无确定版本" in w
        ]
        self.assertEqual(
            len(unmapped_warnings), 1, "生态未映射必须有独立告警条目"
        )
        self.assertEqual(len(no_version_warnings), 1, "无确定版本必须有独立告警条目")
        self.assertIn("weird", unmapped_warnings[0])
        self.assertIn("mystery", no_version_warnings[0])
        # 不混桶：两种原因不得出现在同一条文案里
        self.assertNotIn("mystery", unmapped_warnings[0])
        self.assertNotIn("weird", no_version_warnings[0])
        self.assertIn("生态系统未映射", warnings_text)
        self.assertIn("无确定版本", warnings_text)


class TestDepsDataVersionNormalization(unittest.TestCase):
    """外部 deps_data 入口的 version 归一化（伪版本不得送 OSV）。"""

    def test_pseudo_versions_normalized(self):
        data = {
            "packages": [
                {"name": "root", "version": "1.0.0", "ecosystem": "npm", "is_root": True},
                {"name": "a", "version": "^1.2.0", "ecosystem": "npm"},
                {"name": "b", "version": "1.2.x", "ecosystem": "npm"},
                {"name": "c", "version": "*", "ecosystem": "npm"},
                {"name": "d", "version": "latest", "ecosystem": "npm"},
                {"name": "e", "version": "2.3.4", "ecosystem": "npm"},
                {"name": "f", "version": "", "ecosystem": "npm"},
            ],
            "edges": [],
        }
        packages, edges = da._deps_data_to_graph(data)
        by_name = {p.name: p for p in packages}
        self.assertEqual(by_name["a"].version, "1.2.0", "范围串取下界")
        self.assertTrue(by_name["a"].version_inferred)
        self.assertEqual(by_name["b"].version, "", "伪版本 1.2.x 必须置空")
        self.assertEqual(by_name["c"].version, "")
        self.assertEqual(by_name["d"].version, "")
        self.assertEqual(by_name["e"].version, "2.3.4")
        self.assertFalse(by_name["e"].version_inferred, "精确版本不算推断")
        self.assertEqual(by_name["f"].version, "")
        self.assertFalse(
            any(p.version == "^1.2.0" or p.version == "1.2.x" for p in packages),
            "原始伪版本不得原样进入图/OSV 查询",
        )
        self.assertEqual(edges, [])


class TestEnrichNoSerialFallback(unittest.TestCase):
    """fetch_many 异常时全员 UNKNOWN，不得逐包串行重试。"""

    def test_batch_failure_marks_all_unknown_without_per_package_retry(self):
        class BatchFailCountsFetch:
            def __init__(self):
                self.fetch_calls = 0

            def fetch_many(self, items):
                raise RuntimeError("registry unreachable")

            def fetch(self, name, eco):
                self.fetch_calls += 1
                return {"description": "", "license": "MIT"}

        fetcher = BatchFailCountsFetch()
        packages = [
            da.DependencyNode(name="demo", version="1.0.0", ecosystem="npm", is_root=True)
        ]
        packages += [
            da.DependencyNode(name=f"pkg{i}", version="1.0.0", ecosystem="npm")
            for i in range(5)
        ]
        info = da.enrich_licenses(packages, fetcher=fetcher)
        self.assertEqual(
            [e["license"] for e in info],
            ["UNKNOWN"] * 5,
            "批量失败必须全员显式 UNKNOWN",
        )
        self.assertEqual(
            fetcher.fetch_calls, 0, "批量失败后禁止逐包串行重试 fetch（性能熔断）"
        )


class _StubAdapter(base_ecosystem.BaseEcosystemAdapter):
    """批量协议测试桩：get_package 记录调用，bad 包抛异常。"""

    ECOSYSTEM_NAME = "stub"

    def __init__(self):
        super().__init__(fetcher=lambda url: None)
        self.requested = []

    def get_package(self, *args):
        name = args[0]
        self.requested.append(name)
        if name == "bad":
            raise RuntimeError("boom")
        return {"name": name, "license": "MIT"}

    def build_package_url(self, *args):
        return ""

    def parse_package_info(self, raw, *args):
        return {}

    def build_search_url(self, keyword):
        return ""

    def parse_search_results(self, raw):
        return {}


class TestBatchProtocol(unittest.TestCase):
    """ecosystem 脚本 --batch：等长对齐 + 单包失败不中断整批。"""

    def test_run_batch_aligned_and_fault_tolerant(self):
        adapter = _StubAdapter()
        results = adapter.run_batch(["a", "bad", "c"])
        self.assertEqual(len(results), 3, "结果必须与请求等长对齐")
        self.assertEqual(results[0], {"name": "a", "license": "MIT"})
        self.assertEqual(results[1], {}, "单包失败必须为 {}，不中断整批")
        self.assertEqual(results[2], {"name": "c", "license": "MIT"})
        self.assertEqual(adapter.requested, ["a", "bad", "c"])

    def test_main_batch_outputs_json_array(self):
        adapter = _StubAdapter()
        buf = io.StringIO()
        with mock.patch("sys.argv", ["stub.py", "--batch", "a", "b"]):
            with redirect_stdout(buf):
                adapter.main()
        data = json.loads(buf.getvalue())
        self.assertIsInstance(data, list)
        self.assertEqual([item["name"] for item in data], ["a", "b"])

    def test_main_batch_requires_arguments(self):
        adapter = _StubAdapter()
        with mock.patch("sys.argv", ["stub.py", "--batch"]):
            with self.assertRaises(SystemExit):
                adapter.main()


class RecordingBatchFetcher(readme_generator.EcosystemFetcher):
    """记录 --batch 调用次数的测试桩。"""

    def __init__(self, batch_results=None, batch_raises=False):
        super().__init__()
        self.batch_calls = []
        self.batch_results = batch_results or {}
        self.batch_raises = batch_raises
        self.per_package_calls = []

    def _fetch_batch_uncached(self, ecosystem, names):
        self.batch_calls.append((ecosystem, list(names)))
        if self.batch_raises:
            raise RuntimeError("batch broken")
        return self.batch_results

    def _fetch_uncached(self, package_name, ecosystem):
        self.per_package_calls.append((package_name, ecosystem))
        return {"description": "", "license": f"per-pkg-{package_name}"}


class TestFetchManyPrefersBatch(unittest.TestCase):
    """EcosystemFetcher.fetch_many：每生态一次 --batch，失败回退逐包。"""

    def test_one_batch_subprocess_per_ecosystem(self):
        fetcher = RecordingBatchFetcher(
            batch_results={
                "lodash": {"description": "d", "license": "MIT"},
                "requests": {"description": "d", "license": "Apache-2.0"},
            }
        )
        results = fetcher.fetch_many(
            [("lodash", "npm"), ("left-pad", "npm"), ("requests", "pypi")]
        )
        batches = {(eco, tuple(names)) for eco, names in fetcher.batch_calls}
        self.assertEqual(
            batches,
            {("npm", ("lodash", "left-pad")), ("pypi", ("requests",))},
            "每个生态系统只允许一次 --batch 子进程",
        )
        self.assertEqual(fetcher.per_package_calls, [], "批量成功时不得走逐包路径")
        self.assertEqual(results[("lodash", "npm")]["license"], "MIT")
        self.assertEqual(results[("requests", "pypi")]["license"], "Apache-2.0")
        # 未命中批量结果的包按失败语义为 {}
        self.assertEqual(results[("left-pad", "npm")], {})

    def test_batch_failure_falls_back_to_per_package(self):
        fetcher = RecordingBatchFetcher(batch_raises=True)
        results = fetcher.fetch_many([("lodash", "npm"), ("requests", "pypi")])
        self.assertEqual(len(fetcher.batch_calls), 2, "每个生态各尝试一次批量")
        self.assertEqual(
            {name for name, _ in fetcher.per_package_calls},
            {"lodash", "requests"},
            "批量失败必须回退逐包子进程路径",
        )
        self.assertEqual(results[("lodash", "npm")]["license"], "per-pkg-lodash")


class TestReadmePrefersDepsDataLicense(unittest.TestCase):
    """readme 许可证列优先取 deps_data（DB 单一数据源），fetcher 仅补缺失。"""

    def test_license_from_deps_data_wins_over_fetcher(self):
        deps_data = {
            "packages": [
                {"name": "a", "version": "1.0.0", "ecosystem": "npm", "license": "MIT"},
                {"name": "b", "version": "1.0.0", "ecosystem": "npm"},
            ],
            "edges": [],
        }

        class Fetcher:
            def fetch(self, name, eco):
                return {"description": f"desc-{name}", "license": "FromFetcher"}

        md = readme_generator.generate_dependency_readme(deps_data, fetcher=Fetcher())
        self.assertIn("| a | 1.0.0 | desc-a | MIT |", md)
        self.assertIn("| b | 1.0.0 | desc-b | FromFetcher |", md)

    def test_license_shown_even_without_fetcher(self):
        deps_data = {
            "packages": [
                {"name": "a", "version": "1.0.0", "ecosystem": "npm", "license": "MIT"},
            ],
            "edges": [],
        }
        md = readme_generator.generate_dependency_readme(deps_data, fetcher=None)
        self.assertIn("| a | 1.0.0 | - | MIT |", md)


if __name__ == "__main__":
    unittest.main()
