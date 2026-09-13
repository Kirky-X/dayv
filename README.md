# Dayv（大禹）— 多生态依赖分析引擎

> 基于 Ladybug 图数据库的依赖分析 skill：依赖树/冲突/漏洞/健康度/升级模拟/配置优化，输出 JSON/HTML/PDF/SBOM。覆盖 7 个生态系统，安全漏洞走 OSV 数据库。

[![GitHub Release](https://img.shields.io/github/v/release/Kirky-X/dayv?style=flat-square)](https://github.com/Kirky-X/dayv/releases)
[![License](https://img.shields.io/github/license/Kirky-X/dayv?style=flat-square)](LICENSE)

中文 | [English](README_EN.md)

## ✨ 功能特性

**11 个子命令**（`dependency_analyzer.py --help` 实测）：

| 子命令 | 说明 | 关键 flag |
| ------ | ---- | --------- |
| `analyze-data` | 分析 LLM 提供的依赖数据 JSON（主入口） | `--conflicts` / `--security` / `--report` / `-o` |
| `analyze` | 分析项目依赖（旧版） | `--visualize`（Mermaid）/ `--impact` |
| `query` | 查询包上下游依赖 | `-e <ecosystem>` |
| `search` | 按关键词搜索包 | `-e <ecosystem>` |
| `security` | 扫描包安全漏洞（OSV） | `-e` / `--priority`（CVSS×0.5+exploit×0.3+business×0.2） |
| `report` | 从 `deps_data.json` 生成报告 | `--format json\|html\|pdf\|sbom` |
| `health` | 5 维度健康度评分 + Mermaid 雷达图 | `-o` |
| `readme` | 生成依赖说明 markdown 章节 | `-o` |
| `simulate` | 升级影响 dry-run（major=high / minor=medium / patch=low） | `--project` |
| `monitor` | 漏洞定时扫描 + webhook 告警 | `--cron` / `--webhook` |
| `optimize` | 依赖配置优化（去重 + 删冗余 + 识别未使用） | `--check dedupe\|redundant\|unused` / `--deep` |

**7 个生态系统**：Python(PyPI) / Node.js(npm) / Java(Maven) / Rust(crates) / Ruby(RubyGems) / PHP(Packagist) / .NET(NuGet)。`security`/`query`/`search` 均支持 `-e` 指定生态。

**核心机制**：Ladybug GraphDB 构建 `Package` / `DependsOn` / `ConflictsWith` / `Vulnerability` 图；漏洞扫描走 [OSV](https://osv.dev/)（CVE/GHSA + 严重度 + 修复版本）；版本推荐必须过 `check_version_constraint` 验证；目录中检测到多类生态配置并存时，显式展示生效/跳过清单后询问扫描范围，不静默缩小范围。

## 📦 安装

```bash
# 同步到 agent 技能目录（~/.zcode/skills 与 ~/.claude/skills）
bash scripts/sync-skills.sh dayv

# 首跑前置：安装依赖（缺依赖时子命令会显式报错提示本步骤，不会裸 traceback 崩溃）
pip install -r requirements.txt
# 方式三：远程安装（GitHub 仓库）
npx skills add Kirky-X/dayv --agent claude-code -y
```

`real-ladybug`（图数据库）为必需；`weasyprint` 仅 PDF 报告需要，未安装时相关子命令显式报错，不影响其他功能。

## 🚀 快速开始

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

`deps_data.json` schema：`{"packages":[{"name","version","ecosystem","is_root"}],"edges":[{"source","target","constraint"}]}`。完整 flag 与输出示例见 [`references/subcommands.md`](references/subcommands.md)。

## ✅ 测试与验证

- **语法**：`python3 -m py_compile scripts/*.py` 实测 20 个脚本全部通过
- **端到端实测**：`analyze-data` 喂入样例 `deps_data.json`（numpy 1.21.0 + pandas/scipy 边）→ 生成 `report.json`，OSV 实时命中 `GHSA-fpfv-jqm9-f5jm`（numpy 1.21.0，medium）；`report --format html` 实测生成 7.2KB HTML
- **回归测试目录未纳入 git**：clone 后不可直接 pytest（根目录仅存 `conftest.py`），验证以各子命令实际运行 + `--help` 输出核对为准
- **已知灰区（如实标注）**：PyPI 无官方搜索 API，`search`/`query` 通过爬取 pypi.org HTML 页面解析（BeautifulSoup），页面标记变更可能导致字段解析为空——实测一次 `query fastapi` 中 `versions` 正常返回但 `latest_version` 为空；`security` 因无法解析最新版本会按设计显式拒绝执行（防假版本误报），此时改用 `analyze-data` 由 LLM 提供版本数据

## 📁 目录结构

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

## 🔮 边界

- **Go 和 C/C++ 不支持**：Go 无中心 registry（依赖走 git modules），C/C++ 无单一中央仓库（vcpkg/conan 分散式），与本 skill「中央包仓库查询」定位不匹配
- 不扫描 `node_modules` / `venv` / `target` 等构建产物目录
- 不用假版本号跑 `security`（必须先查真实最新版，查不到则终止并显式告知）；OSV 无响应时标注"未扫描"，不当"无漏洞"
- 解析失败必须报错位置 + 行号，不静默吞掉继续跑；GraphDB 初始化失败直接终止，不降级

## 📄 License 与归属

[MIT](LICENSE) © Kirky-X。完整配置项、异常处理表与反模式清单见 [`references/architecture.md`](references/architecture.md) 和 [`references/anti-patterns.md`](references/anti-patterns.md)。
