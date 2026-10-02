#!/usr/bin/env python3
"""R5 purl 单点模块回归测试（调研报告建议 5 验收项）。

验收点：
- 7 生态 purl 构造符合 package-url 规范（npm scoped 转义、maven g:a 拆分）
- SPDX SBOM 每个包带 externalRefs PACKAGE-MANAGER purl
- OSV querybatch 查询项携带 purl 字段
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

import purl
import sbom_generator
import dependency_analyzer as da
from dependency_analyzer import DependencyNode


class TestMakePurl:
    def test_seven_ecosystems(self):
        cases = [
            ("requests", "pypi", "2.31.0", "pkg:pypi/requests@2.31.0"),
            ("lodash", "npm", "4.17.21", "pkg:npm/lodash@4.17.21"),
            ("org.springframework:spring-core", "maven", "5.3.0",
             "pkg:maven/org.springframework/spring-core@5.3.0"),
            ("serde", "crates", "1.0.193", "pkg:cargo/serde@1.0.193"),
            ("rails", "rubygems", "7.0.4", "pkg:gem/rails@7.0.4"),
            ("vendor/pkg", "packagist", "1.2.0", "pkg:composer/vendor/pkg@1.2.0"),
            ("Newtonsoft.Json", "nuget", "13.0.3", "pkg:nuget/Newtonsoft.Json@13.0.3"),
        ]
        for name, eco, ver, expected in cases:
            assert purl.make_purl(name, eco, ver) == expected, (name, eco)

    def test_npm_scoped_encoding(self):
        assert purl.make_purl("@babel/core", "npm", "6.0.2") == "pkg:npm/%40babel/core@6.0.2"

    def test_maven_requires_namespace(self):
        assert purl.make_purl("spring-core", "maven", "5.3.0") == "pkg:maven/spring-core@5.3.0"

    def test_unknown_ecosystem_returns_none(self):
        assert purl.make_purl("go.mod", "golang") is None

    def test_no_version_no_suffix(self):
        assert purl.make_purl("requests", "pypi") == "pkg:pypi/requests"

    def test_parse_roundtrip(self):
        for p, eco, name, ver in [
            ("pkg:pypi/requests@2.31.0", "pypi", "requests", "2.31.0"),
            ("pkg:npm/%40babel/core@6.0.2", "npm", "@babel/core", "6.0.2"),
            ("pkg:cargo/serde", "crates", "serde", None),
            ("pkg:maven/org.springframework/spring-core@5.3.0",
             "maven", "org.springframework:spring-core", "5.3.0"),
            ("pkg:composer/vendor/pkg", "packagist", "vendor/pkg", None),
        ]:
            got = purl.parse_purl(p)
            assert got == {"ecosystem": eco, "name": name, "version": ver}, p

    def test_parse_invalid(self):
        assert purl.parse_purl("https://x/y") is None
        assert purl.parse_purl("pkg:unknown/abc") is None

    def test_depsdev_path_full_encoding(self):
        assert purl.depsdev_purl_path("pkg:npm/lodash@4.17.21") == (
            "pkg%3Anpm%2Flodash%404.17.21"
        )


class TestSbomExternalRefs:
    def test_spdx_has_purl_external_ref(self):
        sbom = sbom_generator.generate_sbom(
            packages=[
                {"name": "requests", "version": "2.31.0", "ecosystem": "pypi", "is_root": True},
                {"name": "certifi", "version": "2023.7.22", "ecosystem": "pypi"},
            ],
            edges=[{"source": "requests", "target": "certifi"}],
            project_name="requests",
        )
        certifi = [p for p in sbom["Packages"] if p["Name"] == "certifi"][0]
        refs = certifi["externalRefs"]
        assert refs[0]["referenceCategory"] == "PACKAGE-MANAGER"
        assert refs[0]["referenceType"] == "purl"
        assert refs[0]["referenceLocator"] == "pkg:pypi/certifi@2023.7.22"

    def test_unknown_ecosystem_omits_refs(self):
        sbom = sbom_generator.generate_sbom(
            packages=[{"name": "mystery", "version": "1.0", "ecosystem": "golang"}],
            edges=[],
            project_name="mystery",
        )
        assert "externalRefs" not in sbom["Packages"][0]


class TestOsvQueryPurl:
    def test_query_includes_purl(self):
        q = da._osv_query_for(
            DependencyNode(name="requests", version="2.31.0", ecosystem="pypi")
        )
        assert q["package"]["purl"] == "pkg:pypi/requests@2.31.0"
        assert q["package"]["ecosystem"] == "PyPI"
        assert q["version"] == "2.31.0"

    def test_query_without_version_omits_purl_version(self):
        q = da._osv_query_for(
            DependencyNode(name="lodash", version="", ecosystem="npm")
        )
        assert q["package"]["purl"] == "pkg:npm/lodash"
