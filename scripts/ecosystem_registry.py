#!/usr/bin/env python3
"""Ecosystem Registry — 生态元数据单一注册表（调研建议 R14，参照 syft cataloger 注册表）。

新增生态只改这一个文件：加 ECOSYSTEMS 条目 + DEPENDENCY_FILES 文件映射即可，
全链路（OSV 映射 / 文件检测 / parser 分派 / 子脚本入口 / argparse choices /
SBOM downloadLocation / purl type / deps.dev system）自动跟随。

模块必须保持零第三方依赖：dependency_analyzer / sbom_generator / purl /
depsdev_client 都在重依赖（real_ladybug / httpx）导入失败即退出的链路上。

企业私仓：设置环境变量 DAYV_INDEX_URL_<ECO大写>（如 DAYV_INDEX_URL_MAVEN）
可覆盖对应生态的 registry 基址（index_base_url），缓解 mvnrepository 等反爬。
"""

import os
from typing import Any, Dict, List, Optional

# ============ 生态级元数据 ============
# status 派生自 DEPENDENCY_FILES：该生态任一文件有 parser 即 implemented
ECOSYSTEMS: Dict[str, Dict[str, Any]] = {
    "pypi": {
        "display_name": "Python",
        "readme_name": "PyPI",
        "purl_type": "pypi",
        "osv_ecosystem": "PyPI",
        "depsdev_system": "PYPI",
        "script": "pypi.py",
        "index_url": "https://pypi.org",
        "registry_base_url": "https://pypi.org/project/",
    },
    "npm": {
        "display_name": "Node.js",
        "readme_name": "npm",
        "purl_type": "npm",
        "osv_ecosystem": "npm",
        "depsdev_system": "NPM",
        "script": "npm.py",
        "index_url": "https://registry.npmjs.org",
        "registry_base_url": "https://www.npmjs.com/package/",
    },
    "maven": {
        "display_name": "Java",
        "readme_name": "Maven",
        "purl_type": "maven",
        "osv_ecosystem": "Maven",
        "depsdev_system": "MAVEN",
        "script": "maven.py",
        "index_url": "https://repo1.maven.org/maven2",
        "registry_base_url": "https://repo1.maven.org/maven2/",
    },
    "crates": {
        "display_name": "Rust",
        "readme_name": "crates",
        "purl_type": "cargo",
        "osv_ecosystem": "crates.io",
        "depsdev_system": "CARGO",
        "script": "crates.py",
        "index_url": "https://crates.io",
        "registry_base_url": "https://crates.io/crates/",
    },
    "rubygems": {
        "display_name": "Ruby",
        "readme_name": "RubyGems",
        "purl_type": "gem",
        "osv_ecosystem": "RubyGems",
        "depsdev_system": "RUBYGEMS",
        "script": "rubygems.py",
        "index_url": "https://rubygems.org",
        "registry_base_url": "https://rubygems.org/gems/",
    },
    "packagist": {
        "display_name": "PHP",
        "readme_name": "Packagist",
        "purl_type": "composer",
        "osv_ecosystem": "Packagist",
        "depsdev_system": "PACKAGIST",
        "script": "packagist.py",
        "index_url": "https://repo.packagist.org",
        "registry_base_url": "https://packagist.org/packages/",
    },
    "nuget": {
        "display_name": ".NET",
        "readme_name": "NuGet",
        "purl_type": "nuget",
        "osv_ecosystem": "NuGet",
        "depsdev_system": "NUGET",
        "script": "nuget.py",
        "index_url": "https://api.nuget.org/v3-flatcontainer",
        "registry_base_url": "https://www.nuget.org/packages/",
    },
}

# ============ 依赖文件 → 生态/kind/parser 映射 ============
# parser 为逻辑名（dependency_analyzer.PARSER_FUNCS 的键），None = 检测可识别但
# 自动解析未实现（命中时显式提示，不静默）。lockfile parser 见 R4。
# Go / C/C++ 无中央 registry，按 Non-Goals 不收录（go.mod / conanfile.txt 等）。
DEPENDENCY_FILES: Dict[str, Dict[str, Any]] = {
    # --- manifest ---
    "pyproject.toml": {"ecosystem": "pypi", "kind": "manifest", "parser": "pyproject"},
    "requirements.txt": {"ecosystem": "pypi", "kind": "manifest", "parser": "requirements"},
    "setup.py": {"ecosystem": "pypi", "kind": "manifest", "parser": None},
    "package.json": {"ecosystem": "npm", "kind": "manifest", "parser": "package_json"},
    "pom.xml": {"ecosystem": "maven", "kind": "manifest", "parser": None},
    "build.gradle": {"ecosystem": "maven", "kind": "manifest", "parser": None},
    "build.gradle.kts": {"ecosystem": "maven", "kind": "manifest", "parser": None},
    "Cargo.toml": {"ecosystem": "crates", "kind": "manifest", "parser": None},
    "Gemfile": {"ecosystem": "rubygems", "kind": "manifest", "parser": None},
    "composer.json": {"ecosystem": "packagist", "kind": "manifest", "parser": None},
    # --- lockfile（精确版本来源，优先于 manifest）---
    "package-lock.json": {"ecosystem": "npm", "kind": "lockfile", "parser": "package_lock"},
    "poetry.lock": {"ecosystem": "pypi", "kind": "lockfile", "parser": "poetry_lock"},
    "Cargo.lock": {"ecosystem": "crates", "kind": "lockfile", "parser": "cargo_lock"},
    "composer.lock": {"ecosystem": "packagist", "kind": "lockfile", "parser": "composer_lock"},
    "Gemfile.lock": {"ecosystem": "rubygems", "kind": "lockfile", "parser": "gemfile_lock"},
}

# 扩展名映射（.csproj/.fsproj/.vbproj 等，无 lockfile 形态）
PROJ_EXTENSION_FILES: Dict[str, str] = {
    ".csproj": "nuget",
    ".fsproj": "nuget",
    ".vbproj": "nuget",
}


# ============ 查询辅助（消费方只 import 这些函数） ============


def ecosystem_names() -> List[str]:
    """argparse choices 用：全部支持的生态名（保持声明顺序）。"""
    return list(ECOSYSTEMS.keys())


def eco_meta(ecosystem: str) -> Optional[Dict[str, Any]]:
    """生态元数据条目；未知生态返回 None。"""
    return ECOSYSTEMS.get(ecosystem)


def osv_ecosystem(ecosystem: str) -> Optional[str]:
    """内部生态名 → OSV ecosystem 名（osv-scanner 同源 schema）；未知返回 None。"""
    meta = ECOSYSTEMS.get(ecosystem)
    return meta.get("osv_ecosystem") if meta else None


def purl_type(ecosystem: str) -> Optional[str]:
    """内部生态名 → purl type（package-url 规范）；未知返回 None。"""
    meta = ECOSYSTEMS.get(ecosystem)
    return meta.get("purl_type") if meta else None


def depsdev_system(ecosystem: str) -> Optional[str]:
    """内部生态名 → deps.dev API system 枚举；未知返回 None。"""
    meta = ECOSYSTEMS.get(ecosystem)
    return meta.get("depsdev_system") if meta else None


def script_for(ecosystem: str) -> Optional[str]:
    """生态 → registry 查询子脚本文件名；未知返回 None。"""
    meta = ECOSYSTEMS.get(ecosystem)
    return meta.get("script") if meta else None


def _env_key(ecosystem: str) -> str:
    return f"DAYV_INDEX_URL_{ecosystem.upper()}"


def index_base_url(ecosystem: str) -> str:
    """生态 registry 基址。环境变量 DAYV_INDEX_URL_<ECO> 优先（企业私仓），
    未设置时回退内置默认。子脚本在 import 时取值：CLI 子进程每次启动都会
    重新读环境变量，无需重启任何常驻进程。"""
    meta = ECOSYSTEMS.get(ecosystem)
    default = meta.get("index_url", "") if meta else ""
    return os.environ.get(_env_key(ecosystem), default)


def registry_base_url(ecosystem: str) -> str:
    """包详情页基址（SBOM downloadLocation 用）；未知生态返回空串。"""
    meta = ECOSYSTEMS.get(ecosystem)
    return meta.get("registry_base_url", "") if meta else ""


def file_entry(filename: str) -> Optional[Dict[str, Any]]:
    """依赖文件名 → {ecosystem, kind, parser}；不认识的文件返回 None。"""
    return DEPENDENCY_FILES.get(filename)


def extension_entry(suffix: str) -> Optional[str]:
    """扩展名（.csproj 等）→ 生态名；未收录返回 None。"""
    return PROJ_EXTENSION_FILES.get(suffix.lower())


def detect_files() -> Dict[str, str]:
    """文件名 → 生态名（manifest + lockfile 全集），detect_dependency_file 消费。"""
    return {name: entry["ecosystem"] for name, entry in DEPENDENCY_FILES.items()}


def parser_status() -> List[Dict[str, Any]]:
    """各生态解析能力自省（--list-parsers 消费）。

    返回 [{ecosystem, display_name, status, manifests: [{file, parser}],
    lockfiles: [{file, parser}]}]，status:
    - implemented: 任一 manifest 或 lockfile 有 parser
    - partial: 仅有 lockfile parser（manifest 全部未实现）
    - not_implemented: 全部文件均无 parser
    """
    rows: List[Dict[str, Any]] = []
    for eco, meta in ECOSYSTEMS.items():
        manifests = [
            {"file": name, "parser": entry["parser"]}
            for name, entry in DEPENDENCY_FILES.items()
            if entry["ecosystem"] == eco and entry["kind"] == "manifest"
        ]
        lockfiles = [
            {"file": name, "parser": entry["parser"]}
            for name, entry in DEPENDENCY_FILES.items()
            if entry["ecosystem"] == eco and entry["kind"] == "lockfile"
        ]
        has_manifest_parser = any(m["parser"] for m in manifests)
        has_lockfile_parser = any(l["parser"] for l in lockfiles)
        if has_manifest_parser:
            status = "implemented"
        elif has_lockfile_parser:
            status = "partial"
        else:
            status = "not_implemented"
        rows.append(
            {
                "ecosystem": eco,
                "display_name": meta.get("display_name", eco),
                "status": status,
                "manifests": manifests,
                "lockfiles": lockfiles,
            }
        )
    return rows
