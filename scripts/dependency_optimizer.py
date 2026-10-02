"""dayv optimize: 依赖配置优化（去重 + 删冗余 + 识别未使用）。

三类检测：
1. find_duplicates: 同 name 多 entry（重复声明子依赖，导致配置文件膨胀）
2. find_redundant: 能被其他显式声明包自动引入的传递依赖（冗余手动声明）
3. find_unused: 声明了但代码没 import 的依赖（导致二进制变大）

入口:
    optimize(project_path, deps_data, ecosystem, checks, fetcher) -> dict
    format_optimize_report(result) -> str
    apply_optimization(project_path, ecosystem, result, backup=True) -> dict  # --apply 实际改配置
"""

import json
import re
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from utils import sort_versions


# 各 ecosystem 的 import 扫描正则 + 文件扩展名 + 归一化函数
ECOSYSTEM_SCAN: Dict[str, Dict[str, Any]] = {
    "pypi": {
        "exts": (".py",),
        "patterns": [
            re.compile(r"^\s*import\s+([\w.]+)", re.MULTILINE),
            re.compile(r"^\s*from\s+([\w.]+)\s+import", re.MULTILINE),
        ],
        "normalize": lambda m: m.split(".")[0].replace("-", "_"),
    },
    "npm": {
        "exts": (".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"),
        "patterns": [
            re.compile(r"""require\(\s*['"]([^'"\s]+)['"]\s*\)"""),
            re.compile(r"""from\s+['"]([^'"\s]+)['"]"""),
            re.compile(r"""import\s+['"]([^'"\s]+)['"]"""),
        ],
        "normalize": lambda m: (
            m.split("/", 1)[0]
            if not m.startswith("@")
            else "/".join(m.split("/", 2)[:2])
        ),
    },
    "crates": {
        "exts": (".rs",),
        "patterns": [
            re.compile(r"^\s*use\s+([\w:]+)", re.MULTILINE),
            re.compile(r"^\s*extern\s+crate\s+([\w]+)", re.MULTILINE),
        ],
        "normalize": lambda m: re.split(r"::", m)[0],
    },
    "rubygems": {
        "exts": (".rb",),
        "patterns": [
            re.compile(r"""^\s*require\(\s*['"]([^'"]+)['"]"""),
            re.compile(r"""^\s*require\s+['"]([^'"]+)['"]"""),
        ],
        "normalize": lambda m: m.split("/")[0],
    },
    "maven": {
        "exts": (".java",),
        "patterns": [re.compile(r"^\s*import\s+([\w.]+);", re.MULTILINE)],
        "normalize": lambda m: m,
        "note": "maven 的 import 是 Java 类全名，无法直接映射到 groupId:artifactId，结果需人工确认",
    },
    "packagist": {
        "exts": (".php",),
        "patterns": [re.compile(r"^\s*use\s+([\w\\]+);", re.MULTILINE)],
        "normalize": lambda m: m,
        "note": "PHP use 是命名空间，无法直接映射到 composer 包名，结果需人工确认",
    },
    "nuget": {
        "exts": (".cs",),
        "patterns": [re.compile(r"^\s*using\s+([\w.]+);", re.MULTILINE)],
        "normalize": lambda m: m,
        "note": "C# using 是命名空间，无法直接映射到 NuGet 包名，结果需人工确认",
    },
}

# 构建/依赖产物目录（扫描时跳过，避免误报）
SKIP_DIRS = {
    "node_modules",
    "venv",
    ".venv",
    "env",
    "__pycache__",
    "target",
    "build",
    "dist",
    ".git",
    "vendor",
    "eggs",
    ".eggs",
    "site-packages",
}

# 开发工具白名单（声明但不需要被代码 import 的，如测试/格式化工具）
DEV_TOOLS = {
    "pypi": {
        "pytest",
        "black",
        "mypy",
        "flake8",
        "ruff",
        "isort",
        "tox",
        "build",
        "setuptools",
        "wheel",
        "pip",
        "twine",
        "pytest-cov",
        "coverage",
        "hypothesis",
    },
    "npm": {
        "eslint",
        "prettier",
        "typescript",
        "jest",
        "vitest",
        "vite",
        "webpack",
        "babel",
        "rollup",
        "@types/node",
        "ts-node",
    },
    "crates": set(),
    "rubygems": {"rake", "rspec", "rubocop", "bundler"},
    "maven": {"maven-compiler-plugin", "junit"},
    "packagist": {"phpunit", "php-cs-fixer"},
    "nuget": set(),
}


def _is_local_import(name: str) -> bool:
    """npm 相对路径 import（./foo）跳过。"""
    return name.startswith(".") or name.startswith("/")


def find_duplicates(deps_data: dict) -> List[Dict[str, Any]]:
    """检测重复依赖（同 name 多 entry，重复声明子依赖）。

    返回 [{name, count, entries: [{version, ecosystem, is_root}], suggestion}]
    """
    seen: Dict[str, List[dict]] = {}
    for pkg in deps_data.get("packages", []):
        seen.setdefault(pkg["name"], []).append(pkg)

    duplicates: List[Dict[str, Any]] = []
    for name, entries in seen.items():
        if len(entries) > 1:
            versions = [e.get("version", "") for e in entries]
            duplicates.append(
                {
                    "name": name,
                    "count": len(entries),
                    "entries": [
                        {
                            "version": e.get("version"),
                            "ecosystem": e.get("ecosystem"),
                            "is_root": e.get("is_root"),
                        }
                        for e in entries
                    ],
                    "suggestion": (
                        f"统一 {name} 版本声明，仅保留一个（当前 {len(entries)} 条；"
                        f"建议保留最新稳定版 {sort_versions(versions)[0] if versions else '未知'}）"
                    ),
                }
            )
    return duplicates


def _fetch_explicit_deps(fetcher, explicit: List[dict]) -> Dict[str, dict]:
    """拉取显式声明包的 dependencies 映射，返回 {package_name: dependencies_dict}。

    优先并发：当 fetcher 提供 get_package_many（EcosystemFetcher）时走
    ThreadPoolExecutor 批量查询（registry 包查询并发）；
    否则回退串行 get_package（兼容 MockFetcher 等仅实现单包接口的 fetcher）。
    网络失败包对应位置为空 dict（不抛异常，由上层报告）。
    """
    deps_by_pkg: Dict[str, dict] = {}

    if hasattr(fetcher, "get_package_many"):
        items = [(q["name"], q.get("ecosystem", "")) for q in explicit]
        try:
            infos = fetcher.get_package_many(items)
        except Exception:
            infos = {}
        for q in explicit:
            key = (q["name"], q.get("ecosystem", ""))
            info = infos.get(key, {}) or {}
            deps_by_pkg[q["name"]] = info.get("dependencies", {}) or {}
        return deps_by_pkg

    for q in explicit:
        try:
            info = fetcher.get_package(q["name"]) or {}
        except Exception:
            info = {}  # 网络失败跳过，由上层报告（不静默吞错）
        deps_by_pkg[q["name"]] = info.get("dependencies", {}) or {}
    return deps_by_pkg


def find_redundant(deps_data: dict, fetcher=None) -> List[Dict[str, Any]]:
    """检测冗余传递依赖（能被其他显式声明包自动引入的）。

    fetcher 提供（EcosystemFetcher）→ deep 模式查 registry，准确性高；
    fetcher=None → quick 模式仅基于 edges 分析，准确性有限。

    返回 [{package, reason, 引入方: [names]}]
    """
    packages = deps_data.get("packages", [])
    edges = deps_data.get("edges", [])
    explicit = [p for p in packages if not p.get("is_root")]
    explicit_names = {p["name"] for p in explicit}

    redundant: Dict[str, Dict[str, Any]] = {}

    def _add(pkg_name: str, reason: str, via: str) -> None:
        if pkg_name not in redundant:
            redundant[pkg_name] = {
                "package": pkg_name,
                "reason": reason,
                "引入方": [via],
            }
        elif via not in redundant[pkg_name]["引入方"]:
            redundant[pkg_name]["引入方"].append(via)

    if fetcher is not None:
        # deep 模式：并发拉取每个显式声明包 Q 的 dependencies（_fetch_explicit_deps
        # 优先 get_package_many → ThreadPoolExecutor，回退串行 get_package），
        # 若 Q 的 deps 中包含其他显式声明包 P，则 P 冗余（Q 会自动引入 P）。
        deps_by_pkg = _fetch_explicit_deps(fetcher, explicit)
        for q in explicit:
            q_deps = deps_by_pkg.get(q["name"], {})
            for dep_name in q_deps:
                if dep_name in explicit_names and dep_name != q["name"]:
                    _add(
                        dep_name,
                        f"是 {q['name']} 的传递依赖，{q['name']} 会自动引入它",
                        q["name"],
                    )
    else:
        # quick 模式：基于 edges，若 source（非根）→ target 都是显式声明包，
        # 则 target 冗余（source 声明中已含 target，source 会自动引入 target）
        for edge in edges:
            src, tgt = edge.get("source"), edge.get("target")
            if not src or not tgt or src == tgt:
                continue
            if tgt in explicit_names and src in explicit_names:
                src_pkg = next((p for p in packages if p["name"] == src), None)
                if src_pkg and not src_pkg.get("is_root"):
                    _add(
                        tgt,
                        f"是 {src} 的依赖（edges 中已存在），{src} 会自动引入它",
                        src,
                    )

    return [
        {"package": v["package"], "reason": v["reason"], "引入方": v["引入方"]}
        for v in redundant.values()
    ]


def _scan_imports(project_path: str, ecosystem: str) -> Set[str]:
    """扫描项目代码 import，返回归一化后的包名集合。"""
    config = ECOSYSTEM_SCAN.get(ecosystem)
    if not config:
        return set()

    exts = config["exts"]
    patterns = config["patterns"]
    normalize = config["normalize"]
    root = Path(project_path)
    if not root.is_dir():
        return set()

    imports: Set[str] = set()
    for f in root.rglob("*"):
        if not f.is_file() or f.suffix not in exts:
            continue
        if any(part in SKIP_DIRS for part in f.parts):
            continue
        try:
            text = f.read_text(encoding="utf-8", errors="ignore")
        except (OSError, UnicodeDecodeError):
            continue
        for pat in patterns:
            for m in pat.finditer(text):
                name = m.group(1)
                if ecosystem == "npm" and _is_local_import(name):
                    continue
                imports.add(normalize(name))
    return imports


def find_unused(project_path: str, deps_data: dict, ecosystem: str) -> Dict[str, Any]:
    """检测未使用的依赖（声明了但代码没 import，导致二进制变大）。

    返回 {declared_count, used, used_count, unused, unused_count, note}
    """
    config = ECOSYSTEM_SCAN.get(ecosystem)
    if not config:
        return {
            "declared_count": 0,
            "used": [],
            "used_count": 0,
            "unused": [],
            "unused_count": 0,
            "note": f"ecosystem {ecosystem} 暂不支持 unused 检测",
        }

    normalize = config["normalize"]
    declared = [
        p["name"] for p in deps_data.get("packages", []) if not p.get("is_root")
    ]
    declared_norm = {normalize(n) for n in declared}

    used = _scan_imports(project_path, ecosystem)
    used_norm = {normalize(u) for u in used}

    tools = DEV_TOOLS.get(ecosystem, set())
    tools_norm = {normalize(t) for t in tools}

    unused: List[str] = []
    for name in declared:
        n = normalize(name)
        if n in used_norm:
            continue  # 代码引用中
        if n in tools_norm:
            continue  # 开发工具
        unused.append(name)

    return {
        "declared_count": len(set(declared)),
        "used": sorted(used),
        "used_count": len(used),
        "unused": sorted(unused),
        "unused_count": len(unused),
        "note": config.get("note", ""),
    }


def optimize(
    project_path: str,
    deps_data: dict,
    ecosystem: str,
    checks: Optional[List[str]] = None,
    fetcher=None,
) -> dict:
    """主入口：运行指定检测，返回报告 dict。

    checks: ["dedupe", "redundant", "unused"]；None 表示全部
    fetcher: EcosystemFetcher 实例（可选，redundant deep 模式用）
    """
    if checks is None:
        checks = ["dedupe", "redundant", "unused"]
    result: Dict[str, Any] = {
        "project_path": project_path,
        "ecosystem": ecosystem,
        "total_packages": len(deps_data.get("packages", [])),
        "checks_run": list(checks),
        "redundant_mode": "deep" if fetcher is not None else "quick",
    }

    if "dedupe" in checks:
        result["duplicates"] = find_duplicates(deps_data)
    if "redundant" in checks:
        result["redundant"] = find_redundant(deps_data, fetcher=fetcher)
    if "unused" in checks:
        result["unused"] = find_unused(project_path, deps_data, ecosystem)

    return result


def format_optimize_report(result: dict) -> str:
    """格式化 optimize 结果为可读文本。"""
    eco = result.get("ecosystem", "?")
    lines: List[str] = [
        f"依赖配置优化报告 · {result.get('project_path', '?')} (ecosystem={eco})",
        f"总包数: {result.get('total_packages', 0)}"
        f" | checks: {', '.join(result.get('checks_run', []))}"
        f" | redundant 模式: {result.get('redundant_mode', '?')}",
        "=" * 70,
    ]

    if "duplicates" in result:
        dups = result["duplicates"]
        lines.append(f"\n【1】重复依赖 (duplicates): {len(dups)} 处")
        if dups:
            for d in dups:
                lines.append(f"  ⚠️ {d['name']} (×{d['count']})")
                for e in d["entries"]:
                    lines.append(
                        f"      - version={e['version']}, "
                        f"ecosystem={e['ecosystem']}, is_root={e['is_root']}"
                    )
                lines.append(f"      💡 {d['suggestion']}")
        else:
            lines.append("  ✅ 无重复声明")

    if "redundant" in result:
        reds = result["redundant"]
        mode = result.get("redundant_mode", "quick")
        lines.append(f"\n【2】冗余传递依赖 (redundant, {mode} 模式): {len(reds)} 处")
        if reds:
            for r in reds:
                lines.append(f"  ⚠️ {r['package']}")
                lines.append(f"      reason: {r['reason']}")
                lines.append(
                    f"      💡 可删除显式声明，由 {', '.join(r['引入方'])} 自动引入"
                )
        else:
            lines.append(
                "  ✅ 无冗余声明"
                if mode == "deep"
                else "  ✅ 基于 edges 无冗余（quick 模式有限，建议 --deep 查 registry 确认）"
            )

    if "unused" in result:
        un = result["unused"]
        if isinstance(un, dict):
            unused_list = un.get("unused", [])
            lines.append(
                f"\n【3】未使用依赖 (unused): {len(unused_list)} 个 "
                f"(声明 {un.get('declared_count', 0)}, 代码引用 {un.get('used_count', 0)})"
            )
            if unused_list:
                for u in unused_list:
                    lines.append(f"  ⚠️ {u} — 代码未引用，可移除（避免二进制变大）")
            else:
                lines.append("  ✅ 所有声明依赖均被使用")
            if un.get("note"):
                lines.append(f"  📝 {un['note']}")

    return "\n".join(lines)


# ============ --apply：实际改配置文件（带 backup） ============


def _norm_pypi(name: str) -> str:
    """PEP 503 规范化：小写 + 把 -_. 合并为 -（用于跨书写形式匹配）。"""
    return re.sub(r"[-_.]+", "-", name).lower()


def _norm_npm(name: str) -> str:
    """npm 包名规范化：保留 @scope/ 结构，仅小写。"""
    return name.strip().lower()


def _locate_config_file(project_path: str, ecosystem: str) -> Optional[Path]:
    """在 project_path 定位可写的依赖配置文件。

    仅返回 --apply 能安全处理的文件类型（requirements.txt / package.json）。
    其余（pyproject.toml / Cargo.toml / Gemfile / composer.json）返回 None → 上层提示人工应用。
    """
    root = Path(project_path)
    if root.is_file():
        root = root.parent
    if not root.is_dir():
        return None

    candidates = {
        "pypi": ["requirements.txt"],
        "npm": ["package.json"],
    }.get(ecosystem, [])
    for name in candidates:
        p = root / name
        if p.is_file():
            return p
    return None


def _apply_requirements(  # noqa: C901 - 分支多但线性
    path: Path, remove_set: Set[str], backup: bool
) -> Dict[str, Any]:
    """编辑 requirements.txt：删除 remove_set 中的包声明行（保留注释/指令/空行）。"""
    backup_path = None
    if backup:
        backup_path = Path(str(path) + ".dayv.bak")
        shutil.copy2(path, backup_path)

    removed: List[str] = []
    kept_lines: List[str] = []
    skipped: List[str] = []
    name_re = re.compile(r"^\s*([A-Za-z0-9_.-]+)\s*(?:\[.+?\])?\s*[<>=!~#]")

    text = path.read_text(encoding="utf-8")
    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        # 不触碰注释、空行、子指令（-r/-e/.）、路径行
        if (
            not stripped
            or stripped.startswith("#")
            or stripped.startswith("-")
            or stripped.startswith("git+")
            or "://" in stripped
        ):
            kept_lines.append(raw_line)
            continue
        # 提取包名（含仅包名行）
        m = name_re.match(raw_line)
        candidate = None
        if m:
            candidate = m.group(1)
        else:
            bare = re.match(r"^\s*([A-Za-z0-9_.-]+)\s*$", raw_line)
            if bare:
                candidate = bare.group(1)
        if candidate is None:
            kept_lines.append(raw_line)
            continue
        if _norm_pypi(candidate) in remove_set:
            removed.append(candidate)
            continue  # 丢弃此行
        kept_lines.append(raw_line)

    path.write_text(
        "\n".join(kept_lines) + ("\n" if text.endswith("\n") else ""), encoding="utf-8"
    )
    return {
        "removed": removed,
        "skipped": skipped,
        "backup_path": str(backup_path) if backup_path else None,
    }


def _apply_package_json(
    path: Path, remove_set: Set[str], backup: bool
) -> Dict[str, Any]:
    """编辑 package.json：从 dependencies/devDependencies 删除 remove_set 中的 key。"""
    backup_path = None
    if backup:
        backup_path = Path(str(path) + ".dayv.bak")
        shutil.copy2(path, backup_path)

    data = json.loads(path.read_text(encoding="utf-8"))
    removed: List[str] = []
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        deps = data.get(section, {})
        if not isinstance(deps, dict):
            continue
        for key in list(deps.keys()):
            if _norm_npm(key) in remove_set:
                del deps[key]
                removed.append(key)

    path.write_text(
        json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    return {
        "removed": removed,
        "backup_path": str(backup_path) if backup_path else None,
    }


def apply_optimization(
    project_path: str,
    ecosystem: str,
    result: Dict[str, Any],
    backup: bool = True,
) -> Dict[str, Any]:
    """把 optimize() 的 unused 检测结果实际写入配置文件（带 backup）。

    安全范围：
    - 仅应用 find_unused 的"未使用依赖"（最高置信度：声明但代码无引用）
    - duplicates/redundant 不自动改（version 合并需人工判断，避免误删必需版本约束）
    - pyproject.toml / Cargo.toml / Gemfile / composer.json 等不支持的文件 →
      applied=False + reason，由调用方提示人工应用，绝不静默谎称已应用

    Args:
        project_path: 项目路径
        ecosystem: pypi / npm / ...
        result: optimize() 返回的 dict
        backup: True 则写 .dayv.bak 备份（默认开，破坏性操作的默认安全姿态）

    Returns:
        {applied: bool, file: str|None, backup_path: str|None,
         removed: [...], reason: str（未应用时说明）}
    """
    unused = result.get("unused") or {}
    names = unused.get("unused", []) if isinstance(unused, dict) else []
    if not names:
        return {
            "applied": False,
            "file": None,
            "backup_path": None,
            "removed": [],
            "reason": "无 unused 依赖可移除",
        }

    config_path = _locate_config_file(project_path, ecosystem)
    if config_path is None:
        return {
            "applied": False,
            "file": None,
            "backup_path": None,
            "removed": [],
            "reason": (
                f"--apply 暂不支持 ecosystem={ecosystem} 的配置文件"
                f"（仅支持 pypi/requirements.txt、npm/package.json）；请人工应用"
            ),
        }

    normalize = _norm_pypi if ecosystem == "pypi" else _norm_npm
    remove_set = {normalize(n) for n in names}

    if config_path.name == "requirements.txt":
        outcome = _apply_requirements(config_path, remove_set, backup)
    elif config_path.name == "package.json":
        outcome = _apply_package_json(config_path, remove_set, backup)
    else:  # 防御：_locate_config_file 只会返回上面两种，但仍兜底
        return {
            "applied": False,
            "file": str(config_path),
            "backup_path": None,
            "removed": [],
            "reason": f"--apply 不支持文件 {config_path.name}，请人工应用",
        }

    return {
        "applied": True,
        "file": str(config_path),
        "backup_path": outcome.get("backup_path"),
        "removed": outcome.get("removed", []),
        "reason": ""
        if outcome.get("removed")
        else "配置文件中未匹配到任何 unused 依赖行",
    }
