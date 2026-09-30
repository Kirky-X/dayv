#!/usr/bin/env python3
"""G1 回归测试：健康度"许可证合规"维度必须基于真实 license 数据评分。

修复前:
- health_scorer._score_license 读 report["license_info"]，
  但 dependency_analyzer.report_to_dict 从不产出该字段 →
  权重 0.15 的维度恒为常数 75.0（占位符）。
- 依赖数据收集环节完全没有 license 采集。

修复后:
- enrich_licenses 批量查 registry 补全 license（写入 properties["license"]，
  与图数据库/SBOM 同源）；无法获取的包显式标 "UNKNOWN"，不静默跳过。
- generate_report 采集 → AnalysisReport.license_info → report_to_dict 输出
  → score_health 按真实数据评分。
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

import dependency_analyzer as da
import health_scorer
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
        da.DependencyNode(name="mystery", version="1.0.0", ecosystem="npm"),
    ]
    edges = [
        da.DependencyEdge(source="demo", target="lodash", constraint="^4.17.21"),
        da.DependencyEdge(source="demo", target="gplpkg", constraint="^2.0.0"),
        da.DependencyEdge(source="demo", target="mystery", constraint="*"),
    ]
    analyzer.build_dependency_graph(packages, edges)
    return packages


class TestEnrichLicenses(unittest.TestCase):
    """enrich_licenses：单一数据源 + 失败显式标注。"""

    def test_fills_properties_and_returns_license_info(self):
        packages = [
            da.DependencyNode(name="demo", version="1.0.0", ecosystem="npm", is_root=True),
            da.DependencyNode(name="lodash", version="4.17.21", ecosystem="npm"),
            da.DependencyNode(name="gplpkg", version="2.0.0", ecosystem="npm"),
        ]
        info = da.enrich_licenses(
            packages, fetcher=MapLicenseFetcher({"lodash": "MIT", "gplpkg": "GPL-3.0"})
        )
        by_name = {p.name: p for p in packages}
        self.assertEqual(by_name["lodash"].properties["license"], "MIT")
        self.assertEqual(by_name["gplpkg"].properties["license"], "GPL-3.0")
        # 返回列表与非根包等长同序
        self.assertEqual(
            [e["package"] for e in info], ["lodash", "gplpkg"]
        )

    def test_unavailable_license_marked_unknown_not_silent(self):
        packages = [
            da.DependencyNode(name="demo", version="1.0.0", ecosystem="npm", is_root=True),
            da.DependencyNode(name="mystery", version="1.0.0", ecosystem="npm"),
        ]
        info = da.enrich_licenses(packages, fetcher=MapLicenseFetcher({}))
        self.assertEqual(
            info,
            [{"package": "mystery", "license": "UNKNOWN"}],
            "查询不到 license 必须显式标 UNKNOWN，禁止静默留空/跳过",
        )

    def test_fetcher_failure_degrades_to_unknown_explicitly(self):
        packages = [
            da.DependencyNode(name="demo", version="1.0.0", ecosystem="npm", is_root=True),
            da.DependencyNode(name="mystery", version="1.0.0", ecosystem="npm"),
        ]
        info = da.enrich_licenses(packages, fetcher=FailingLicenseFetcher())
        self.assertEqual(info[0]["license"], "UNKNOWN", "查询器故障也应显式标 UNKNOWN")

    def test_root_package_is_excluded(self):
        packages = [
            da.DependencyNode(name="demo", version="1.0.0", ecosystem="npm", is_root=True),
        ]
        info = da.enrich_licenses(packages, fetcher=MapLicenseFetcher({}))
        self.assertEqual(info, [], "根包是项目自身，不属于依赖许可证合规范围")


class TestLicenseInfoFlowsThroughReport(unittest.TestCase):
    """端到端：generate_report → report_to_dict 输出真实 license_info。"""

    def test_report_dict_contains_real_license_data(self):
        analyzer = make_analyzer({"lodash": "MIT", "gplpkg": "GPL-3.0", "mystery": ""})
        try:
            build_demo_graph(analyzer)
            report = analyzer.generate_report("demo")
            report_dict = analyzer.report_to_dict(report)
        finally:
            analyzer.close()

        licenses = {e["package"]: e["license"] for e in report_dict["license_info"]}
        self.assertEqual(licenses.get("lodash"), "MIT", "报告应携带真实 license")
        self.assertEqual(licenses.get("gplpkg"), "GPL-3.0")
        self.assertEqual(
            licenses.get("mystery"), "UNKNOWN", "获取失败的包应显式标 UNKNOWN"
        )


class TestLicenseDimensionReactsToData(unittest.TestCase):
    """核心回归：license_compliance 维度分必须随真实数据变化（不再恒 75.0）。"""

    def _score_with(self, license_map):
        analyzer = make_analyzer(license_map)
        try:
            build_demo_graph(analyzer)
            report = analyzer.generate_report("demo")
            report_dict = analyzer.report_to_dict(report)
        finally:
            analyzer.close()
        return health_scorer.score_health(report_dict)

    def test_mixed_licenses_score_matches_manual_calculation(self):
        result = self._score_with({"lodash": "MIT", "gplpkg": "GPL-3.0", "mystery": ""})
        # MIT=100, GPL=40, UNKNOWN=50 → (100+40+50)/3 = 63.3
        self.assertAlmostEqual(
            result["dimensions"]["license_compliance"],
            63.3,
            msg="维度分应等于真实许可证数据的加权计算值",
        )

    def test_all_permissive_licenses_score_full(self):
        result = self._score_with({"lodash": "MIT", "gplpkg": "Apache-2.0", "mystery": "BSD-3-Clause"})
        self.assertEqual(
            result["dimensions"]["license_compliance"],
            100.0,
            "全部宽松许可证应得满分（区别于修复前的常数 75.0）",
        )

    def test_scores_differ_when_license_data_differs(self):
        permissive = self._score_with({"lodash": "MIT", "gplpkg": "MIT", "mystery": "MIT"})
        restrictive = self._score_with({"lodash": "GPL-3.0", "gplpkg": "AGPL-3.0", "mystery": "GPL-2.0"})
        self.assertGreater(
            permissive["dimensions"]["license_compliance"],
            restrictive["dimensions"]["license_compliance"],
            "许可证数据不同，维度分必须不同（数据流真实打通的证据）",
        )


class TestScoreLicensePureFunction(unittest.TestCase):
    """_score_license：标准 dict 条目 + 旧 List[str] 格式向后兼容。"""

    def test_dict_entries_scored_by_risk(self):
        report = {
            "license_info": [
                {"package": "a", "license": "MIT"},
                {"package": "b", "license": "LGPL-3.0"},
                {"package": "c", "license": "GPL-3.0"},
                {"package": "d", "license": "UNKNOWN"},
            ]
        }
        # (100 + 70 + 40 + 50) / 4 = 65.0
        self.assertEqual(health_scorer._score_license(report), 65.0)

    def test_legacy_string_list_still_supported(self):
        report = {"license_info": ["MIT", "Apache-2.0"]}
        self.assertEqual(health_scorer._score_license(report), 100.0)

    def test_missing_license_info_returns_neutral(self):
        self.assertEqual(health_scorer._score_license({}), 75.0)


if __name__ == "__main__":
    unittest.main()
