#!/usr/bin/env python3
"""G2 回归测试：SBOM 的 LicenseConcluded 必须来自真实 license 数据。

修复前:
- sbom_generator.generate_sbom 读 pkg["license"]（缺失回退 NOASSERTION），
  但 dependency_analyzer._to_deps_data 从不产出 license 键 →
  所有包的 LicenseConcluded 恒为 NOASSERTION。

修复后:
- _to_deps_data 输出 license 键（取自 node.properties["license"]，
  与 enrich_licenses / 图数据库 / 健康度评分同一数据源）。
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

import dependency_analyzer as da
import sbom_generator
from _mocks import MapLicenseFetcher


class TestToDepsDataCarriesLicense(unittest.TestCase):
    """_to_deps_data：license 键取自 properties["license"]（同源）。"""

    def test_outputs_license_from_properties(self):
        enriched = da.DependencyNode(
            name="lodash", version="4.17.21", ecosystem="npm",
            properties={"license": "MIT"},
        )
        bare = da.DependencyNode(name="mystery", version="1.0.0", ecosystem="npm")
        deps = da._to_deps_data([enriched, bare], [])
        self.assertEqual(
            deps["packages"][0]["license"],
            "MIT",
            "deps_data 应携带 properties 中的真实 license",
        )
        self.assertEqual(deps["packages"][1]["license"], "")

    def test_root_package_license_also_carried(self):
        root = da.DependencyNode(
            name="demo", version="1.0.0", ecosystem="npm", is_root=True,
            properties={"license": "Apache-2.0"},
        )
        deps = da._to_deps_data([root], [])
        self.assertEqual(deps["packages"][0]["license"], "Apache-2.0")


class TestSbomUsesRealLicenseConcluded(unittest.TestCase):
    """SBOM 输出：有 license 用真实值，无 license 才回退 NOASSERTION。"""

    def test_license_concluded_reflects_real_data(self):
        packages = [
            {"name": "lodash", "version": "4.17.21", "ecosystem": "npm", "license": "MIT"},
            {"name": "mystery", "version": "1.0.0", "ecosystem": "npm", "license": ""},
        ]
        sbom = sbom_generator.generate_sbom(packages, [], "demo")
        by_name = {p["Name"]: p for p in sbom["Packages"]}
        self.assertEqual(
            by_name["lodash"]["LicenseConcluded"],
            "MIT",
            "有真实 license 数据时 LicenseConcluded 必须是真实值（不再恒 NOASSERTION）",
        )
        self.assertEqual(
            by_name["mystery"]["LicenseConcluded"],
            "NOASSERTION",
            "确实无数据时按 SPDX 规范回退 NOASSERTION",
        )


class TestEnrichToSbomEndToEnd(unittest.TestCase):
    """同源链路：enrich_licenses → _to_deps_data → generate_sbom。"""

    def test_single_source_pipeline_produces_real_concluded_license(self):
        packages = [
            da.DependencyNode(name="demo", version="1.0.0", ecosystem="npm", is_root=True),
            da.DependencyNode(name="requests", version="2.28.0", ecosystem="pypi"),
            da.DependencyNode(name="left-pad", version="1.3.0", ecosystem="npm"),
        ]
        edges = [
            da.DependencyEdge(source="demo", target="requests", constraint=">=2.28.0"),
            da.DependencyEdge(source="demo", target="left-pad", constraint="*"),
        ]
        da.enrich_licenses(
            packages, fetcher=MapLicenseFetcher({"requests": "Apache-2.0"})
        )
        deps = da._to_deps_data(packages, edges)
        sbom = sbom_generator.generate_sbom(deps["packages"], deps["edges"], "demo")
        by_name = {p["Name"]: p for p in sbom["Packages"]}
        self.assertEqual(
            by_name["requests"]["LicenseConcluded"],
            "Apache-2.0",
            "enrich 采集的 license 应沿同一条数据流直达 SBOM",
        )
        self.assertEqual(
            by_name["left-pad"]["LicenseConcluded"],
            "NOASSERTION",
            "未采集到 license 的包显式 NOASSERTION",
        )


if __name__ == "__main__":
    unittest.main()
