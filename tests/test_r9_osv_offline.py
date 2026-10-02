#!/usr/bin/env python3
"""R9 OSV 离线库 + TTL 缓存回归测试（调研报告建议 9 验收项）。

验收点：
- --offline 只查本地库：已下载生态出结果、未下载生态显性提示（不发网络请求）
- 复杂受影响区间保守跳过并计数（可能漏报显性化）
- TTL 缓存命中不重复发请求；防误报例外：推断版本整批 TTL ≤300s
- download_offline_db 解压 + meta 落盘（http_get 注入离线）
"""

import io
import json
import os
import sys
import time
import zipfile

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

import osv_offline
import dependency_analyzer as da
from dependency_analyzer import DependencyNode
import _mocks  # noqa: F401  （CapturingHttpClient，tests/ 目录在 pytest sys.path）


# ============ TTL 缓存 ============


class TestCache:
    def test_roundtrip_and_expiry(self, tmp_path):
        osv_offline.cache_write("pypi", "requests", "2.31.0", [{"id": "X"}], cache_dir=str(tmp_path))
        got = osv_offline.cache_read("pypi", "requests", "2.31.0", 600, cache_dir=str(tmp_path))
        assert got == [{"id": "X"}]
        # 过期：mtime 拨回 2 小时前
        p = osv_offline.cache_path("pypi", "requests", "2.31.0", str(tmp_path))
        old = time.time() - 7200
        os.utime(p, (old, old))
        assert osv_offline.cache_read("pypi", "requests", "2.31.0", 600, cache_dir=str(tmp_path)) is None
        # 未过期仍可读（余量放大避免边界抖动）
        assert osv_offline.cache_read("pypi", "requests", "2.31.0", 100_000, cache_dir=str(tmp_path)) == [{"id": "X"}]

    def test_special_chars_in_name(self, tmp_path):
        osv_offline.cache_write("npm", "@scope/pkg", "1.0.0", [], cache_dir=str(tmp_path))
        assert osv_offline.cache_read("npm", "@scope/pkg", "1.0.0", 60, cache_dir=str(tmp_path)) == []

    def test_effective_ttl_inferred_exception(self):
        # 防误报例外：推断版本整批 TTL 收敛 ≤300s；None 表示禁用
        assert osv_offline.effective_ttl(86400, any_inferred=True) == 300
        assert osv_offline.effective_ttl(86400, any_inferred=False) == 86400
        assert osv_offline.effective_ttl(None, any_inferred=True) is None
        assert osv_offline.effective_ttl(60, any_inferred=True) == 60


# ============ 离线库下载与查询 ============


def _fake_zip_bytes(vulns):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for v in vulns:
            z.writestr(f"{v['id']}.json", json.dumps(v))
    return buf.getvalue()


VULN_SIMPLE = {
    "id": "GHSA-test-simple",
    "aliases": ["CVE-2026-0001"],
    "affected": [
        {
            "package": {"ecosystem": "PyPI", "name": "requests"},
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": [
                        {"introduced": "2.3.0"},
                        {"fixed": "2.31.0"},
                    ],
                }
            ],
        }
    ],
}

VULN_COMPLEX = {
    "id": "GHSA-test-complex",
    "affected": [
        {
            "package": {"ecosystem": "PyPI", "name": "flask"},
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": [
                        {"introduced": "0"},
                        {"last_affected": "2.0.0"},
                    ],
                }
            ],
        }
    ],
}


class TestDownload:
    def test_download_extracts_and_meta(self, tmp_path):
        data = _fake_zip_bytes([VULN_SIMPLE, VULN_COMPLEX])
        meta = osv_offline.download_offline_db(
            ["pypi"], dest_dir=str(tmp_path), http_get=lambda url: data
        )
        assert meta["pypi"]["vulns"] == 2
        assert (tmp_path / "pypi" / "GHSA-test-simple.json").is_file()
        assert osv_offline.db_meta("pypi", str(tmp_path))["downloaded_at"]

    def test_download_failure_raises(self, tmp_path):
        def boom(url):
            raise RuntimeError("network down")

        with pytest.raises(RuntimeError):
            osv_offline.download_offline_db(
                ["pypi"], dest_dir=str(tmp_path), http_get=boom
            )


class TestOfflineQuery:
    def _setup_db(self, tmp_path, vulns, eco="pypi"):
        eco_dir = tmp_path / eco
        eco_dir.mkdir(parents=True)
        for v in vulns:
            (eco_dir / f"{v['id']}.json").write_text(json.dumps(v), encoding="utf-8")

    def test_hit_and_version_filtering(self, tmp_path):
        self._setup_db(tmp_path, [VULN_SIMPLE])
        pkgs = [
            DependencyNode(name="requests", version="2.30.0", ecosystem="pypi"),
            DependencyNode(name="requests", version="2.31.0", ecosystem="pypi"),
        ]
        results, skipped = osv_offline.offline_query(pkgs, db_dir=str(tmp_path))
        assert len(results[0]["vulns"]) == 1  # 2.30.0 在 [2.3.0, 2.31.0) 内
        assert results[1]["vulns"] == []  # 2.31.0 已修复
        assert skipped["offline_db_missing"] == []

    def test_introduced_zero_affects_all_until_fix(self, tmp_path):
        vuln = {
            "id": "GHSA-zero",
            "affected": [
                {
                    "package": {"ecosystem": "PyPI", "name": "flask"},
                    "ranges": [
                        {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.0.0"}]}
                    ],
                }
            ],
        }
        self._setup_db(tmp_path, [vuln])
        results, _ = osv_offline.offline_query(
            [DependencyNode(name="flask", version="0.5.0", ecosystem="pypi")],
            db_dir=str(tmp_path),
        )
        assert len(results[0]["vulns"]) == 1

    def test_missing_db_explicit(self, tmp_path):
        results, skipped = osv_offline.offline_query(
            [DependencyNode(name="react", version="18.0.0", ecosystem="npm")],
            db_dir=str(tmp_path),
        )
        assert results == [{}]
        assert len(skipped["offline_db_missing"]) == 1
        assert "npm" in skipped["offline_db_missing"][0]

    def test_complex_range_skipped_and_flagged(self, tmp_path):
        self._setup_db(tmp_path, [VULN_COMPLEX])
        results, skipped = osv_offline.offline_query(
            [DependencyNode(name="flask", version="1.9.9", ecosystem="pypi")],
            db_dir=str(tmp_path),
        )
        assert results[0]["vulns"] == []  # 保守不判
        assert len(skipped["complex_ranges"]) == 1

    def test_name_case_insensitive_pypi(self, tmp_path):
        self._setup_db(tmp_path, [VULN_SIMPLE])
        results, _ = osv_offline.offline_query(
            [DependencyNode(name="Requests", version="2.5.0", ecosystem="pypi")],
            db_dir=str(tmp_path),
        )
        assert len(results[0]["vulns"]) == 1


# ============ analyzer 集成：--offline 不发网络请求 ============


class TestAnalyzerOfflineIntegration:
    def test_query_osv_batch_offline_no_http(self, tmp_path):
        eco_dir = tmp_path / "pypi"
        eco_dir.mkdir()
        (eco_dir / "GHSA-test-simple.json").write_text(
            json.dumps(VULN_SIMPLE), encoding="utf-8"
        )

        class FailHTTP:
            def post(self, *a, **k):
                raise AssertionError("离线模式不允许发网络请求")

        analyzer = da.DependencyAnalyzer(
            db_path=str(tmp_path / "g.db"),
            http_client=FailHTTP(),
            offline_db=True,
            osv_db_dir=str(tmp_path),
            cache_ttl=None,
        )
        try:
            pkgs = [
                DependencyNode(name="requests", version="2.30.0", ecosystem="pypi"),
                DependencyNode(name="unknown-eco-pkg", version="1.0.0", ecosystem="golang"),
            ]
            vulns, skipped, inferred = analyzer._query_osv_batch(pkgs)
            assert len(vulns) == 1
            assert vulns[0].cve_id == "CVE-2026-0001"  # alias 解析正常
            assert len(skipped["unmapped_ecosystem"]) == 1  # golang 未映射
        finally:
            analyzer.close()

    def test_cache_hit_avoids_second_post(self, tmp_path):
        calls = {"n": 0}

        class CountingHTTP:
            def post(self, url, json=None, headers=None):
                calls["n"] += 1
                n = len(json["queries"])

                class R:
                    def json(self_inner):
                        return {"results": [{} for _ in range(n)]}

                return R()

        analyzer = da.DependencyAnalyzer(
            db_path=str(tmp_path / "g.db"),
            http_client=CountingHTTP(),
            osv_db_dir=str(tmp_path),
            cache_dir=str(tmp_path / "cache"),
            cache_ttl=3600,
        )
        try:
            pkgs = [DependencyNode(name="requests", version="2.31.0", ecosystem="pypi")]
            analyzer._query_osv_batch(pkgs)
            assert calls["n"] == 1
            analyzer._query_osv_batch(pkgs)
            assert calls["n"] == 1  # 第二次命中缓存，不再请求
        finally:
            analyzer.close()

    def test_scan_warnings_surface_offline_skips(self, tmp_path):
        analyzer = da.DependencyAnalyzer(
            db_path=str(tmp_path / "g.db"),
            http_client=_mocks.CapturingHttpClient(),
            offline_db=True,
            osv_db_dir=str(tmp_path / "empty"),  # 未下载
            cache_ttl=None,
        )
        try:
            pkg = DependencyNode(name="requests", version="2.31.0", ecosystem="pypi")
            analyzer.db.add_package(pkg)
            analyzer.build_dependency_graph([pkg], [])
            report = analyzer.generate_report("requests")
            joined = "\n".join(report.scan_warnings)
            assert "离线库未下载" in joined
        finally:
            analyzer.close()
