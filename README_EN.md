# Dayv — Multi-Ecosystem Dependency Analysis Engine

> A dependency analysis skill built on the Ladybug graph database: dependency trees / conflicts / vulnerabilities / health scores / upgrade simulation / config optimization, with JSON/HTML/PDF/SBOM output. Covers 7 ecosystems; security vulnerabilities go through the OSV database.

English | [中文](README.md)

[![GitHub Release](https://img.shields.io/github/v/release/Kirky-X/dayv?style=flat-square)](https://github.com/Kirky-X/dayv/releases)
[![License](https://img.shields.io/github/license/Kirky-X/dayv?style=flat-square)](LICENSE)

## ✨ Features

**11 subcommands** (measured via `dependency_analyzer.py --help`):

| Subcommand | Description | Key flags |
| ------ | ---- | --------- |
| `analyze-data` | Analyzes dependency-data JSON provided by the LLM (main entry) | `--conflicts` / `--security` / `--report` / `--rules` / `--baseline` / `--ignore-known` / `--from-sbom` / `--exit-code N` |
| `analyze` | Analyzes project dependencies (lockfile-first) | `--visualize` (Mermaid) / `--impact` / `--list-parsers` |
| `query` | Queries a package's upstream/downstream dependencies | `-e <ecosystem>` |
| `search` | Searches packages by keyword | `-e <ecosystem>` |
| `security` | Scans packages for security vulnerabilities (OSV) | `-e` / `--priority` / `--exit-code N` / `--offline` / `--download-offline-db` / `--config` |
| `report` | Generates reports from `deps_data.json` | `--format json\|html\|pdf\|sarif\|cyclonedx\|sbom` / `--allowed-licenses` |
| `health` | 5-dimension health scoring + Mermaid radar chart | `-o` / `--allowed-licenses` / `--license-categories` / `--scorecard` |
| `readme` | Generates a dependency-notes markdown section | `-o` |
| `simulate` | Upgrade-impact dry-run (major=high / minor=medium / patch=low) | `--project` |
| `monitor` | Scheduled vulnerability scans + webhook alerting | `--cron` / `--webhook` / `--offline` / `--cache` |
| `optimize` | Dependency-config optimization (dedupe + remove redundancy + detect unused) | `--check dedupe\|redundant\|unused` / `--deep` / `--apply` |

**CI exit-code contract**: `0` = success; `N` = `--exit-code N` and vulnerabilities found; `128` = input/parse failure.

**7 ecosystems**: Python(PyPI) / Node.js(npm) / Java(Maven) / Rust(crates) / Ruby(RubyGems) / PHP(Packagist) / .NET(NuGet). `security`/`query`/`search` all support `-e` to specify the ecosystem.

**Core mechanics**: Ladybug GraphDB builds the `Package` / `DependsOn` / `ConflictsWith` / `Vulnerability` graph; vulnerability scanning goes through [OSV](https://osv.dev/) (CVE/GHSA + severity + fixed versions, purl-only query contract); version recommendations must pass `check_version_constraint` validation; lockfiles take precedence over manifests (exact versions eliminate range lower-bound approximations); when multiple ecosystem config types coexist in one directory, the effective/skipped list is shown explicitly — never silently narrowed.

**Governance capabilities**: vulnerability exemption list (`.dayv.toml`, with expiry dates and alias chaining, listed explicitly in reports), license whitelist compliance (`--allowed-licenses`, UNKNOWN bucketed separately), declarative rule engine (`.dayv/rules.json`, forbidden/allowed/required), violation baseline (`--baseline`/`--ignore-known` fail only on new violations), OSV offline DB + TTL cache, dual-standard SBOM (SPDX + CycloneDX with purl throughout, rescannable by osv-scanner/trivy), SARIF 2.1.0 for the GitHub Security tab, and deps.dev transitive-graph enrichment (minimal-parse fallback for ecosystems without full parsers).

## 📦 Installation

```bash
# Sync into the agent skill directories (run from the skills workspace root; the script is not in this repo)
bash ../scripts/sync-skills.sh dayv   # or the repo-root install-skill.sh

# 首跑前置：安装依赖（缺依赖时子命令会显式报错提示本步骤，不会裸 traceback 崩溃）
pip install -r requirements.txt
# Option 3: Remote install (GitHub repo)
npx skills add Kirky-X/dayv --agent claude-code -y
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

- **Syntax**: `python3 -m py_compile scripts/*.py` measured — all 29 scripts pass
- **End-to-end measurement**: feeding the sample `deps_data.json` (numpy 1.21.0 + pandas/scipy edges) into `analyze-data` → produces `report.json`, with an OSV live hit `GHSA-fpfv-jqm9-f5jm` (numpy 1.21.0, medium); `report --format html` measured to produce a 7.2KB HTML file
- **Regression tests**: `tests/` is tracked in git — run `python -m pytest tests/ -q` directly after cloning (fully offline with mocks, no network); additionally `python3 scripts/skill_lint.py .` gates doc consistency (SKILL.md subcommand table vs CLI --help)
- **Known gray zone (reported honestly)**: PyPI has no official search API, so `search`/`query` parse scraped pypi.org HTML pages (BeautifulSoup); page markup changes may cause fields to parse as empty — in one measured `query fastapi` run, `versions` returned normally while `latest_version` came back empty; when `security` cannot parse the latest version it refuses to run by design (to prevent false positives from fake versions) — in that case, use `analyze-data` and let the LLM supply version data

## 📁 Directory Structure

```
dayv/
├── SKILL.md                  # 入口：子命令决策树 + 工作流 + 红线
├── requirements.txt          # real-ladybug/httpx/jinja2 等
├── conftest.py               # pytest 配置
├── tests/                    # offline regression tests (doc-consistency gate included)
├── references/               # subcommands / architecture / anti-patterns 文档
├── lint-checks.json          # skill_lint self-check rules (cli-subcommands doc gate)
└── scripts/                  # 29 scripts (single-file, self-contained, pure Python)
    ├── dependency_analyzer.py    # main engine (11 subcommands)
    ├── ecosystem_registry.py     # single-source ecosystem metadata registry
    ├── base_ecosystem.py         # shared 7-ecosystem adapter (fetch→parse unified schema)
    ├── purl.py                   # Package URL single-point build/parse
    ├── report_renderer.py        # JSON/HTML/PDF/SARIF rendering
    ├── sbom_generator.py         # SPDX 2.3 + CycloneDX 1.5 SBOM
    ├── health_scorer.py          # 5-dimension health scoring + radar chart
    ├── dependency_optimizer.py   # dedupe / redundancy / unused detection
    ├── exemptions.py / license_policy.py / osv_offline.py / rule_engine.py
    ├── violation_baseline.py / depsdev_client.py / monitor.py / simulator.py / ...
    └── pypi.py / npm.py / maven.py / crates.py / rubygems.py / packagist.py / nuget.py
```

## 🔮 Boundaries

- **Go and C/C++ are not supported**: Go has no central registry (dependencies go through git modules) and C/C++ has no single central repository (vcpkg/conan are decentralized), which does not match this skill's "central package repository query" positioning
- Does not scan build-artifact directories such as `node_modules` / `venv` / `target`
- Never runs `security` with fabricated version numbers (the real latest version must be looked up first; if it cannot be found, terminate and state it explicitly); when OSV is unresponsive, mark "not scanned" rather than "no vulnerabilities"
- Parse failures must report the location + line number — never silently swallowed while execution continues; GraphDB initialization failure terminates immediately, with no degradation

## 📄 License & Attribution

[MIT](LICENSE) © Kirky-X. For the full configuration fields, exception-handling table, and anti-pattern list, see [`references/architecture.md`](references/architecture.md) and [`references/anti-patterns.md`](references/anti-patterns.md).
