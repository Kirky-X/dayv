#!/usr/bin/env python3
"""R4 lockfile 解析器回归测试（调研报告建议 4 验收项）。

验收点：
- 5 种 lockfile（package-lock.json/poetry.lock/Cargo.lock/composer.lock/Gemfile.lock）
  解析出精确版本节点，version_resolved=True 且 version_inferred=False
- 根节点来自同目录 manifest（或 lockfile 自身根条目）
- 根约束边 + lockfile 内部依赖边
- 含 lockfile 的项目 analyze 不再依赖范围下界近似
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

import dependency_analyzer as da


def _by_name(packages):
    return {p.name: p for p in packages if not p.is_root}


# ============ package-lock.json v3 ============

PACKAGE_LOCK = {
    "name": "demo",
    "version": "1.0.0",
    "lockfileVersion": 3,
    "packages": {
        "": {
            "name": "demo",
            "version": "1.0.0",
            "dependencies": {"express": "^4.18.0"},
            "devDependencies": {"jest": "^29.0.0"},
        },
        "node_modules/express": {
            "version": "4.18.2",
            "dependencies": {"accepts": "~1.3.8"},
        },
        "node_modules/@scope/pkg": {"version": "2.1.0"},
        "node_modules/accepts": {"version": "1.3.8"},
        "node_modules/jest": {"version": "29.7.0"},
    },
}


class TestPackageLock:
    def test_parse_versions_and_flags(self):
        tmp = _tmp_file("package-lock.json", json.dumps(PACKAGE_LOCK))
        packages, edges = da.parse_package_lock_json(str(tmp))
        by_name = _by_name(packages)
        assert by_name["express"].version == "4.18.2"
        assert by_name["express"].version_resolved is True
        assert by_name["express"].version_inferred is False
        assert by_name["@scope/pkg"].version == "2.1.0"

    def test_root_and_constraint_edges(self):
        tmp = _tmp_file("package-lock.json", json.dumps(PACKAGE_LOCK))
        packages, edges = da.parse_package_lock_json(str(tmp))
        roots = [p for p in packages if p.is_root]
        assert roots and roots[0].name == "demo"
        edge_pairs = {(e.source, e.target, e.constraint) for e in edges}
        assert ("demo", "express", "^4.18.0") in edge_pairs
        assert ("demo", "jest", "^29.0.0") in edge_pairs
        assert ("express", "accepts", "~1.3.8") in edge_pairs

    def test_v1_lockfile_exits_explicitly(self, capsys):
        import pytest

        tmp = _tmp_file("package-lock.json", json.dumps({"lockfileVersion": 1, "dependencies": {}}))
        with pytest.raises(SystemExit) as exc:
            da.parse_package_lock_json(str(tmp))
        # R3 退出码契约：manifest/lockfile 解析失败 = 128
        assert exc.value.code == da.EXIT_INPUT_ERROR


# ============ poetry.lock ============

POETRY_LOCK = """\
[[package]]
name = "requests"
version = "2.31.0"
description = "Python HTTP for Humans."
optional = false

[[package]]
name = "certifi"
version = "2023.7.22"
optional = false

[metadata]
lock-version = "2.0"
"""

PYPROJECT = """\
[project]
name = "demo-py"
version = "0.3.0"
dependencies = ["requests>=2.28", "not-in-lock>=1.0"]
"""


class TestPoetryLock:
    def test_parse_with_sibling_manifest(self, tmp_path):
        (tmp_path / "poetry.lock").write_text(POETRY_LOCK, encoding="utf-8")
        (tmp_path / "pyproject.toml").write_text(PYPROJECT, encoding="utf-8")
        packages, edges = da.parse_poetry_lock(str(tmp_path / "poetry.lock"))
        by_name = _by_name(packages)
        assert by_name["requests"].version == "2.31.0"
        assert by_name["requests"].version_resolved is True
        roots = [p for p in packages if p.is_root]
        assert roots[0].name == "demo-py"
        assert ("demo-py", "requests", ">=2.28") in {
            (e.source, e.target, e.constraint) for e in edges
        }

    def test_parse_without_manifest(self, tmp_path):
        lock = tmp_path / "poetry.lock"
        lock.write_text(POETRY_LOCK, encoding="utf-8")
        packages, edges = da.parse_poetry_lock(str(lock))
        assert len([p for p in packages if not p.is_root]) == 2
        assert edges == []


# ============ Cargo.lock ============

CARGO_LOCK = """\
version = 3

[[package]]
name = "libc"
version = "0.2.147"

[[package]]
name = "getrandom"
version = "0.2.10"
dependencies = ["libc 0.2.147", "cfg-if"]
"""

CARGO_TOML = """\
[package]
name = "demo-rs"
version = "0.1.0"

[dependencies]
getrandom = "0.2"
libc = "0.2"
"""


class TestCargoLock:
    def test_parse_with_inner_edges(self, tmp_path):
        (tmp_path / "Cargo.lock").write_text(CARGO_LOCK, encoding="utf-8")
        (tmp_path / "Cargo.toml").write_text(CARGO_TOML, encoding="utf-8")
        packages, edges = da.parse_cargo_lock(str(tmp_path / "Cargo.lock"))
        by_name = _by_name(packages)
        assert by_name["getrandom"].version == "0.2.10"
        assert by_name["getrandom"].version_resolved is True
        pairs = {(e.source, e.target) for e in edges}
        assert ("getrandom", "libc") in pairs  # 内部边
        assert ("demo-rs", "getrandom") in pairs  # 根约束边
        assert ("getrandom", "cfg-if") not in pairs  # 未锁定的目标跳过


# ============ composer.lock ============

COMPOSER_LOCK = {
    "packages": [
        {
            "name": "vendor/pkg",
            "version": "1.2.0",
            "require": {"php": ">=8.0", "vendor/other": "^2.0"},
        },
        {"name": "vendor/other", "version": "2.3.0"},
    ],
    "packages-dev": [{"name": "phpunit/phpunit", "version": "10.4.2"}],
}

COMPOSER_JSON = {
    "name": "acme/demo",
    "require": {"vendor/pkg": "^1.2", "php": ">=8.1"},
}


class TestComposerLock:
    def test_parse_groups_and_edges(self, tmp_path):
        (tmp_path / "composer.lock").write_text(json.dumps(COMPOSER_LOCK), encoding="utf-8")
        (tmp_path / "composer.json").write_text(json.dumps(COMPOSER_JSON), encoding="utf-8")
        packages, edges = da.parse_composer_lock(str(tmp_path / "composer.lock"))
        by_name = {p.name: p for p in packages if not p.is_root}
        assert by_name["vendor/pkg"].version == "1.2.0"
        assert by_name["vendor/pkg"].version_resolved is True
        assert by_name["phpunit/phpunit"].properties["group"] == "dev"
        pairs = {(e.source, e.target, e.constraint) for e in edges}
        assert ("acme/demo", "vendor/pkg", "^1.2") in pairs
        assert ("vendor/pkg", "vendor/other", "^2.0") in pairs
        # 平台依赖（php/ext-*）不建边
        assert all(t != "php" for (_, t, _) in pairs)


# ============ Gemfile.lock ============

GEMFILE_LOCK = """\
GEM
  remote: https://rubygems.org/
  specs:
    actionpack (7.0.4)
      actionview (= 7.0.4)
      rack (~> 2.2)
    rack (2.2.8)

PLATFORMS
  x86_64-linux

DEPENDENCIES
  actionpack
  rack (~> 2.2)

BUNDLED WITH
   2.4.10
"""


class TestGemfileLock:
    def test_parse_specs_and_edges(self, tmp_path):
        lock = tmp_path / "Gemfile.lock"
        lock.write_text(GEMFILE_LOCK, encoding="utf-8")
        packages, edges = da.parse_gemfile_lock(str(lock))
        by_name = _by_name(packages)
        assert by_name["actionpack"].version == "7.0.4"
        assert by_name["actionpack"].version_resolved is True
        pairs = {(e.source, e.target, e.constraint) for e in edges}
        assert ("actionpack", "rack", "~> 2.2") in pairs
        # 根节点 = 目录名
        roots = [p for p in packages if p.is_root]
        assert roots[0].name == tmp_path.name

    def test_dependencies_section_root_edges(self, tmp_path):
        lock = tmp_path / "Gemfile.lock"
        lock.write_text(GEMFILE_LOCK, encoding="utf-8")
        packages, edges = da.parse_gemfile_lock(str(lock))
        root_name = [p.name for p in packages if p.is_root][0]
        dep_edges = [e for e in edges if e.source == root_name]
        targets = {e.target for e in dep_edges}
        assert {"actionpack", "rack"} == targets


# ============ 集成：detect 优先 lockfile 且 parse_dependencies 走通 ============


class TestParseDependenciesIntegration:
    def test_project_with_lock_only(self, tmp_path):
        (tmp_path / "package-lock.json").write_text(
            json.dumps(PACKAGE_LOCK), encoding="utf-8"
        )
        packages, edges, eco = da.parse_dependencies(str(tmp_path))
        assert eco == "npm"
        by_name = _by_name(packages)
        assert by_name["express"].version_resolved is True

    def test_deps_data_roundtrip_version_resolved(self):
        data = {
            "packages": [
                {"name": "a", "version": "1.0.0", "ecosystem": "npm", "is_root": True},
                {
                    "name": "b",
                    "version": "2.0.0",
                    "ecosystem": "npm",
                    "version_resolved": True,
                },
                {"name": "c", "version": "^1.2.0", "ecosystem": "npm"},
            ],
            "edges": [],
        }
        packages, edges = da._deps_data_to_graph(data)
        by_name = {p.name: p for p in packages}
        assert by_name["b"].version_resolved is True
        assert by_name["b"].version_inferred is False
        assert by_name["c"].version_inferred is True
        assert by_name["c"].version == "1.2.0"


# ============ 工具 ============


def _tmp_file(name: str, content: str):
    import tempfile
    from pathlib import Path

    d = tempfile.mkdtemp(prefix="dayv_r4_")
    f = Path(d) / name
    f.write_text(content, encoding="utf-8")
    return f
