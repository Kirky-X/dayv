#!/usr/bin/env python3
"""审查修复回归测试（独立复审 HIGH/MEDIUM 项的回归锚点）。

- HIGH: OSV 翻页 result 级 next_page_token（不再死代码截断）
- M-2: 缓存路径 "../" 拦截
- M-3: SBOM 默认输出名清洗
- M-6: CycloneDX license 表达式走 expression 字段
- M-7: allowed 多规则只报一次
- M-9: SBOM 反向输入无 purl 时生态留空（不假定 pypi）
- M-10: pom 带 scope 子元素的依赖块不漏检
- L-15: hyphen 右侧通配段
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

import osv_offline
import sbom_generator
import rule_engine
import purl as purl_mod
import license_policy as lp
import dependency_analyzer as da
from dependency_analyzer import DependencyNode
from utils import check_version_constraint


class TestHighPagination:
    def test_page_token_followed_per_result(self):
        """result 级 next_page_token 必须被续拉（此前从响应顶层取 → 死代码截断）。"""
        page1_vulns = [{"id": "GHSA-1"}]
        page2_vulns = [{"id": "GHSA-2"}]
        calls = []

        class PageHTTP:
            def post(self, url, json=None, headers=None):
                calls.append(json)
                if "page_token" not in json["queries"][0]:
                    return _FakeResp({"results": [{"vulns": page1_vulns, "next_page_token": "tok1"}]})
                return _FakeResp({"results": [{"vulns": page2_vulns}]})

        analyzer = da.DependencyAnalyzer(
            db_path=":memory:" if False else None,
            http_client=PageHTTP(),
            cache_ttl=None,
        )
        try:
            pkg = DependencyNode(name="requests", version="2.3.0", ecosystem="pypi")
            vulns, skipped, _ = analyzer._query_osv_batch([pkg])
            assert len(calls) == 2
            assert calls[1]["queries"][0]["page_token"] == "tok1"
            ids = [v.cve_id for v in vulns]
            assert "GHSA-1" in ids and "GHSA-2" in ids
        finally:
            analyzer.close()


class _FakeResp:
    def __init__(self, payload):
        self._payload = payload

    def json(self):
        return self._payload


class TestPathTraversal:
    def test_cache_path_blocks_dotdot(self, tmp_path):
        p = osv_offline.cache_path("npm", "../../evil", "1.0", cache_dir=str(tmp_path))
        assert ".." not in str(p)
        assert tmp_path in p.parents or str(p).startswith(str(tmp_path))

    def test_safe_filename(self):
        f = sbom_generator.safe_filename("../../evil")
        assert "/" not in f and ".." not in f
        assert sbom_generator.safe_filename("demo") == "demo"

    def test_write_sbom_default_path_sanitized(self, tmp_path):
        got = sbom_generator.write_sbom(
            [{"name": "../evil", "version": "1.0", "ecosystem": "pypi", "is_root": True}],
            [],
            "../../evil",
            output_path=str(tmp_path / "out.spdx.json"),
        )
        assert got == str(tmp_path / "out.spdx.json")


class TestCdxLicenseExpression:
    def test_expression_field_for_dual_license(self):
        cdx = sbom_generator.generate_cyclonedx(
            [{"name": "pkg", "version": "1.0", "ecosystem": "npm",
              "license": "(MIT OR Apache-2.0)"}],
            [], "demo",
        )
        lic = cdx["components"][0]["licenses"][0]
        assert "expression" in lic and "license" not in lic

    def test_single_id_still_uses_id(self):
        cdx = sbom_generator.generate_cyclonedx(
            [{"name": "pkg", "version": "1.0", "ecosystem": "npm", "license": "MIT"}],
            [], "demo",
        )
        assert cdx["components"][0]["licenses"][0]["license"]["id"] == "MIT"


class TestAllowedDedup:
    def test_two_allowed_rules_single_violation_per_pkg(self):
        rules = [
            {"name": "白名单A", "type": "allowed", "severity": "warn", "to": "^a$"},
            {"name": "白名单B", "type": "allowed", "severity": "info", "to": "^b$"},
        ]
        deps = {"packages": [{"name": "other", "version": "1.0"}], "edges": []}
        violations = rule_engine.evaluate_rules(rules, deps)
        assert len(violations) == 1
        assert violations[0]["rule"] == "白名单A"


class TestSbomReverseEcosystem:
    def test_no_purl_ecosystem_empty_not_pypi(self, tmp_path):
        spdx = {
            "SPDXVersion": "SPDX-2.3",
            "Packages": [
                {"Name": "mystery", "VersionInfo": "1.0", "SPDXID": "SPDXRef-P1",
                 "LicenseConcluded": "NOASSERTION"}
            ],
            "Relationships": [],
        }
        f = tmp_path / "x.spdx.json"
        f.write_text(json.dumps(spdx), encoding="utf-8")
        data = da._sbom_to_deps_data(f)
        assert data["packages"][0]["ecosystem"] == ""  # 不假定 pypi

    def test_cdx_root_purl_parsed(self, tmp_path):
        cdx = {
            "bomFormat": "CycloneDX",
            "metadata": {"component": {
                "type": "application", "bom-ref": "r",
                "name": "demo", "version": "1.0",
                "purl": "pkg:npm/demo@1.0.0"}},
            "components": [],
            "dependencies": [],
        }
        f = tmp_path / "x.cdx.json"
        f.write_text(json.dumps(cdx), encoding="utf-8")
        data = da._sbom_to_deps_data(f)
        assert data["packages"][0]["ecosystem"] == "npm"


class TestPomTwoStage:
    def test_scope_block_not_dropped(self, tmp_path):
        pom = tmp_path / "pom.xml"
        pom.write_text(
            """<project>
  <groupId>com.demo</groupId><artifactId>demo</artifactId><version>1.0</version>
  <dependencies>
    <dependency>
      <groupId>junit</groupId><artifactId>junit</artifactId><version>4.13.2</version>
      <scope>test</scope>
    </dependency>
    <dependency>
      <groupId>commons-io</groupId><artifactId>commons-io</artifactId>
      <optional>true</optional>
    </dependency>
  </dependencies>
</project>""",
            encoding="utf-8",
        )
        packages, edges, root_name, root_version = da._parse_pom_xml_minimal(pom, "maven")
        names = {p.name for p in packages}
        assert "junit:junit" in names  # 带 scope 的块不再整包漏检
        assert "commons-io:commons-io" in names


class TestLowFixes:
    def test_hyphen_wildcard_right(self):
        assert check_version_constraint("1.5.0", "1.2.3 - 2.x") is True
        assert check_version_constraint("3.0.0", "1.2.3 - 2.x") is False

    def test_parse_purl_strips_qualifiers(self):
        got = purl_mod.parse_purl("pkg:npm/foo@1.0?arch=x86#sub")
        assert got["version"] == "1.0"

    def test_classify_plus_variant(self):
        assert lp.classify_license("GPL-2.0+") == "copyleft"

    def test_lockfile_root_version_empty(self, tmp_path):
        lock = tmp_path / "poetry.lock"
        lock.write_text('[[package]]\nname = "a"\nversion = "1.0"\n', encoding="utf-8")
        packages, _ = da.parse_poetry_lock(str(lock))
        assert packages[0].version == ""  # 不编造 0.0.0

    def test_dup_version_note_attached(self, tmp_path):
        lock = {
            "name": "demo",
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "demo", "version": "1.0.0"},
                "node_modules/a": {"version": "1.0.0"},
                "node_modules/x/node_modules/a": {"version": "2.0.0"},
            },
        }
        f = tmp_path / "package-lock.json"
        f.write_text(json.dumps(lock), encoding="utf-8")
        packages, _ = da.parse_package_lock_json(str(f))
        notes = packages[0].properties.get("manifest_notes", [])
        assert any("同名多版本" in n for n in notes)

    def test_exit_code_arg_validation(self):
        assert da._exit_code_arg("1") == 1
        try:
            da._exit_code_arg("300")
            assert False, "应拒绝超范围"
        except Exception as e:
            assert "0-255" in str(e)
