# Dayv — Multi-Ecosystem Dependency Analysis Engine

> A dependency analysis skill built on the Ladybug graph database: dependency trees / conflicts / vulnerabilities / health scores / upgrade simulation / config optimization, with JSON/HTML/PDF/SBOM output. Covers 7 ecosystems; security vulnerabilities go through the OSV database.

English | [中文](README.md)

[![GitHub Release](https://img.shields.io/github/v/release/Kirky-X/dayv?style=flat-square)](https://github.com/Kirky-X/dayv/releases)
[![License](https://img.shields.io/github/license/Kirky-X/dayv?style=flat-square)](LICENSE)

## ✨ Features

**11 subcommands** (measured via `dependency_analyzer.py --help`):

| Subcommand | Description | Key flags |
| ------ | ---- | --------- |
| `analyze-data` | Analyzes dependency-data JSON provided by the LLM (main entry) | `--conflicts` / `--security` / `--report` / `-o` |
| `analyze` | Analyzes project dependencies (legacy) | `--visualize` (Mermaid) / `--impact` |
| `query` | Queries a package's upstream/downstream dependencies | `-e <ecosystem>` |
| `search` | Searches packages by keyword | `-e <ecosystem>` |
| `security` | Scans packages for security vulnerabilities (OSV) | `-e` / `--priority` (CVSS×0.5+exploit×0.3+business×0.2) |
| `report` | Generates reports from `deps_data.json` | `--format json\|html\|pdf\|sbom` |
| `health` | 5-dimension health scoring + Mermaid radar chart | `-o` |
| `readme` | Generates a dependency-notes markdown section | `-o` |
| `simulate` | Upgrade-impact dry-run (major=high / minor=medium / patch=low) | `--project` |
| `monitor` | Scheduled vulnerability scans + webhook alerting | `--cron` / `--webhook` |
| `optimize` | Dependency-config optimization (dedupe + remove redundancy + detect unused) | `--check dedupe\|redundant\|unused` / `--deep` |

**7 ecosystems**: Python(PyPI) / Node.js(npm) / Java(Maven) / Rust(crates) / Ruby(RubyGems) / PHP(Packagist) / .NET(NuGet). `security`/`query`/`search` all support `-e` to specify the ecosystem.

**Core mechanics**: Ladybug GraphDB builds the `Package` / `DependsOn` / `ConflictsWith` / `Vulnerability` graph; vulnerability scanning goes through [OSV](https://osv.dev/) (CVE/GHSA + severity + fixed versions); version recommendations must pass `check_version_constraint` validation; when multiple ecosystem config types are detected coexisting in one directory, the effective/skipped list is shown explicitly and the scan scope is asked for — never silently narrowed.

## 📦 Installation

```bash
# 同步到 agent 技能目录（~/.zcode/skills 与 ~/.claude/skills）
bash scripts/sync-skills.sh dayv

# 首跑前置：安装依赖（缺依赖时子命令会显式报错提示本步骤，不会裸 traceback 崩溃）
pip install -r requirements.txt
```

`real-ladybug` (the graph database) is required; `weasyprint` is only needed for PDF reports — without it, the affected subcommands fail with explicit errors and other functionality is unaffected.

## 🚀 Quick Start

```bash
# 分析项目依赖树（输入为 LLM 整理的依赖数据 JSON）
python scripts/dependency_analyzer.py analyze-data deps_data.json --report -o report.json

# 查询包（实测：fastapi → 0.141.1，versions 列表实时返回）
python scripts/dependency_analyzer.py query fastapi
python scripts/dependency_analyzer.py query react -e npm

# 安全扫描（先查真实最新版本再查 OSV，拒绝用假版本跑）
python scripts/dependency_analyzer.py security requests --priority

# HTML 报告 / 健康度 / 优化
python scripts/dependency_analyzer.py report deps_data.json --format html -o report.html
python scripts/dependency_analyzer.py health /path/to/project
python scripts/dependency_analyzer.py optimize /path/to/project --check unused
```

`deps_data.json` schema: `{"packages":[{"name","version","ecosystem","is_root"}],"edges":[{"source","target","constraint"}]}`. For full flags and output examples, see [`references/subcommands.md`](references/subcommands.md).

## ✅ Tests & Verification

- **Syntax**: `python3 -m py_compile scripts/*.py` measured — all 20 scripts pass
- **End-to-end measurement**: feeding the sample `deps_data.json` (numpy 1.21.0 + pandas/scipy edges) into `analyze-data` → produces `report.json`, with an OSV live hit `GHSA-fpfv-jqm9-f5jm` (numpy 1.21.0, medium); `report --format html` measured to produce a 7.2KB HTML file
- **Regression-test directory not tracked in git**: pytest cannot run directly after cloning (only `conftest.py` remains at the repo root); verification relies on actually running each subcommand plus checking `--help` output
- **Known gray zone (reported honestly)**: PyPI has no official search API, so `search`/`query` parse scraped pypi.org HTML pages (BeautifulSoup); page markup changes may cause fields to parse as empty — in one measured `query fastapi` run, `versions` returned normally while `latest_version` came back empty; when `security` cannot parse the latest version it refuses to run by design (to prevent false positives from fake versions) — in that case, use `analyze-data` and let the LLM supply version data

## 📁 Directory Structure

```
dayv/
├── SKILL.md                  # 入口：子命令决策树 + 工作流 + 红线
├── requirements.txt          # real-ladybug/httpx/jinja2 等
├── conftest.py               # pytest 配置（测试目录未入 git）
├── references/               # subcommands / architecture / anti-patterns 文档
└── scripts/
    ├── dependency_analyzer.py    # 主分析引擎（11 子命令入口）
    ├── base_ecosystem.py         # 7 生态共享 adapter（fetch→parse 统一 schema）
    ├── report_renderer.py        # JSON/HTML/PDF 渲染
    ├── sbom_generator.py         # SPDX 2.3 SBOM
    ├── health_scorer.py          # 5 维度健康度 + 雷达图
    ├── dependency_optimizer.py   # 去重/删冗余/识别未使用
    ├── monitor.py / simulator.py / impact_analyzer.py / visualizer.py / ...
    └── pypi.py / npm.py / maven.py / crates.py / rubygems.py / packagist.py / nuget.py
```

## 🔮 Boundaries

- **Go and C/C++ are not supported**: Go has no central registry (dependencies go through git modules) and C/C++ has no single central repository (vcpkg/conan are decentralized), which does not match this skill's "central package repository query" positioning
- Does not scan build-artifact directories such as `node_modules` / `venv` / `target`
- Never runs `security` with fabricated version numbers (the real latest version must be looked up first; if it cannot be found, terminate and state it explicitly); when OSV is unresponsive, mark "not scanned" rather than "no vulnerabilities"
- Parse failures must report the location + line number — never silently swallowed while execution continues; GraphDB initialization failure terminates immediately, with no degradation

## 📄 License & Attribution

[MIT](LICENSE) © Kirky-X. For the full configuration fields, exception-handling table, and anti-pattern list, see [`references/architecture.md`](references/architecture.md) and [`references/anti-patterns.md`](references/anti-patterns.md).
