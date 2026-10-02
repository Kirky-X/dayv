#!/usr/bin/env python3
"""R1 正确性 bug 修复的回归测试（调研报告建议 1 验收项）。

三组用例：
1. 两段版本号 "9.9" vs "10.0" 必须按数值排序（原 max() 字符串比较得 "9.9"）
2. check_version_constraint 支持 npm 通配（1.2.x / 1.x / *）与 hyphen 区间
3. security --priority 构造 deps_data 时 ecosystem 读取 -e 参数（不再硬编码 pypi）
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

from utils import check_version_constraint, compare_versions, sort_versions
import dependency_optimizer
import dependency_analyzer


# ============ 1. 版本排序：两段版本号按数值比较 ============


class TestVersionOrdering:
    def test_compare_versions_two_segment(self):
        assert compare_versions("9.9", "10.0") == -1
        assert compare_versions("10.0", "9.9") == 1
        assert compare_versions("1.2", "1.2.0") == 0

    def test_sort_versions_two_segment_desc(self):
        assert sort_versions(["9.9", "10.0", "2.3.1"], reverse=True) == [
            "10.0",
            "9.9",
            "2.3.1",
        ]

    def test_find_duplicates_suggestion_uses_semver_max(self):
        deps_data = {
            "packages": [
                {"name": "left-pad", "version": "9.9", "ecosystem": "npm"},
                {"name": "left-pad", "version": "10.0", "ecosystem": "npm"},
            ],
            "edges": [],
        }
        dups = dependency_optimizer.find_duplicates(deps_data)
        assert len(dups) == 1
        # "9.9" > "10.0" 是字符串比较陷阱；semver 排序必须推荐 10.0
        assert "10.0" in dups[0]["suggestion"]
        assert "9.9" not in dups[0]["suggestion"]


# ============ 2. check_version_constraint：npm 通配与 hyphen 区间 ============


class TestWildcards:
    @pytest.mark.parametrize(
        "version,constraint,expected",
        [
            ("1.2.3", "1.2.x", True),
            ("1.2.9", "1.2.x", True),
            ("1.3.0", "1.2.x", False),
            ("1.9.3", "1.2.x", False),
            ("1.2.3", "1.x", True),
            ("2.0.0", "1.x", False),
            ("0.9.9", "1.x", False),
            ("1.2.3", "1.2.*", True),
            ("1.2.3", "*", True),
            ("3.6.1", "x", True),
        ],
    )
    def test_wildcard(self, version, constraint, expected):
        assert check_version_constraint(version, constraint) is expected

    def test_wildcard_with_prerelease_segment(self):
        assert check_version_constraint("1.2.3-beta.1", "1.2.x") is True


class TestHyphenRange:
    @pytest.mark.parametrize(
        "version,constraint,expected",
        [
            ("1.2.3", "1.2.3 - 2.3.4", True),  # 下界含
            ("2.3.4", "1.2.3 - 2.3.4", True),  # 上界含（npm 语义）
            ("1.2.2", "1.2.3 - 2.3.4", False),
            ("2.3.5", "1.2.3 - 2.3.4", False),
            ("1.5.0", "1.2.3 - 2.3.4", True),
            ("2.3.9", "1.2.3 - 2.3", True),  # 上界缺 patch → < 2.4.0
            ("2.4.0", "1.2.3 - 2.3", False),
            ("1.2.3", "1.2 - 2", True),  # 双侧都缺段
            ("2.0.1", "1.2 - 2", True),  # 上界 "2" → < 3.0.0
            ("3.0.0", "1.2 - 2", False),
            ("1.2.3", "1.2.3 - 2.3.4, !=1.5.0", True),  # 逗号复合：两段均满足
            ("1.5.0", "1.2.3 - 2.3.4, !=1.5.0", False),  # 命中排除段
        ],
    )
    def test_hyphen(self, version, constraint, expected):
        assert check_version_constraint(version, constraint) is expected


# ============ 3. security --priority 的 ecosystem 取自 -e ============


class TestSecurityDepsData:
    def test_ecosystem_from_arg_not_hardcoded(self):
        data = dependency_analyzer._security_deps_data("lodash", "4.17.21", "npm")
        assert data["packages"][0]["ecosystem"] == "npm"
        assert data["packages"][0]["is_root"] is True
        assert data["packages"][0]["version"] == "4.17.21"
        assert data["edges"] == []

    def test_default_ecosystem_pypi(self):
        data = dependency_analyzer._security_deps_data("requests", "2.31.0", "pypi")
        assert data["packages"][0]["ecosystem"] == "pypi"
