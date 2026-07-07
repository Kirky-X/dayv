# Architecture Reference

> 工作流、Scripts、Configuration、Dependencies、异常处理、Testing。从 SKILL.md 外移。

## Analysis Workflow

```
项目路径
    │
    ▼
1. 检测依赖配置文件 (pyproject.toml / package.json / Cargo.toml / pom.xml)
   输入: project_path (str)   输出: dep_file (Path) + ecosystem (str)
   🔴 CHECKPOINT · 多生态系统并存: 同目录检测到 ≥2 类配置文件 → STOP，列出检测到的生态系统，询问用户扫描范围（全部 / 单个 / 取消）
    │
    ▼
2. 解析依赖列表
   输入: dep_file   输出: packages: List[DependencyNode], edges: List[DependencyEdge]
   失败分支: parser 未实现（pom.xml/Cargo.toml/Gemfile/composer.json/.csproj）→ 提示改用 query -e <ecosystem>
    │
    ▼
3. 构建依赖关系图 (Ladybug GraphDB)
   输入: packages, edges   输出: DependencyGraphDB 实例
   失败分支: GraphDB 初始化失败 → 终止，不降级（见异常处理表）
    │
    ▼
4. 检测冲突
   输入: graph   输出: conflicts: List[ConflictInfo]
   - 版本约束冲突
   - 循环依赖
   🔴 CHECKPOINT · HIGH 冲突: 发现 severity=HIGH 的冲突 → STOP，输出冲突详情，询问是否继续完整扫描（继续 / 跳过冲突只看漏洞 / 取消）
    │
    ▼
5. 安全漏洞扫描
   输入: graph   输出: vulnerabilities: List[SecurityVulnerability]
   失败分支: OSV API 5xx/超时 → 标注"未扫描，不等于无漏洞"，不默认 success
    │
    ▼
6. 版本推荐
   输入: graph, constraints   输出: recommendations: Dict[pkg, version]
   🔴 CHECKPOINT · 升级前验证: 推荐前必须 check_version_constraint 验证目标版本满足所有约束，不假设最新版即可
    │
    ▼
7. 生成报告 (JSON / 可视化)
   输入: 全部分析结果   输出: report.json (schema: summary/conflicts/vulnerabilities/update_paths/recommendations)
```

## Scripts

| Script                | Purpose                       | 入口函数 | CLI 用法 |
| --------------------- | ----------------------------- | -------- | -------- |
| dependency_analyzer.py| 主分析引擎                    | `main()` | `python dependency_analyzer.py <subcommand> [args]` |
| utils.py              | 版本比较和约束检查工具        | （库模块，不直接运行）| `from utils import check_version_constraint, compare_versions, sort_versions` |
| report_renderer.py    | HTML/PDF/JSON 报告渲染器      | `render_report(report, output, fmt)` | 被 `report --format` 调用 |
| health_scorer.py      | 依赖健康度评分（5 维度）      | `score_health(report_dict)` / `render_radar_mermaid(result)` | 被 `health` 子命令调用 |
| sbom_generator.py     | SPDX 2.3 SBOM 生成器          | `write_sbom(packages, edges, project_name, output)` | 被 `report --format sbom` 调用 |
| visualizer.py         | Mermaid 依赖树可视化          | `render_mermaid_tree(deps_data, depth=3)` | 被 `analyze --visualize` 调用 |
| impact_analyzer.py    | 冲突影响范围分析              | `analyze_conflict_impact(deps_data, conflicts)` / `format_impact_report(impacts)` | 被 `analyze --impact` 调用 |
| readme_generator.py   | 项目依赖 README 生成器        | `generate_dependency_readme(deps_data, fetcher=None)` + `EcosystemFetcher` | 被 `readme` 子命令调用 |
| simulator.py          | 升级影响模拟（dry-run）       | `simulate_upgrade(deps_data, package, target_version, ecosystem, fetcher=None)` / `format_simulation_report(result)` | 被 `simulate` 子命令调用 |
| vulnerability_prioritizer.py | 漏洞修复优先级排序     | `prioritize_vulnerabilities(vulns, deps_data)` / `format_priority_report(prioritized)` | 被 `security --priority` 调用 |
| monitor.py            | 漏洞持续监控                  | `run_scan()` / `compare_with_history()` / `send_alert()` / `generate_cron_entry()` / `format_alert()` / `save_scan_to_history()` | 被 `monitor` 子命令调用 |
| pypi.py               | PyPI 包信息获取               | `get_package(name)` / `search_packages(keyword)` | `python pypi.py <package>` 或 `python pypi.py --search <keyword>` |
| npm.py                | npm 包信息获取                | `get_package(name)` / `search_packages(keyword)` | `python npm.py <package>` 或 `python npm.py --search <keyword>` |
| maven.py              | Maven 包信息获取              | `get_package(group:artifact)` | `python maven.py <groupId>:<artifactId>` |
| crates.py             | crates.io 包信息获取          | `get_package(crate)` | `python crates.py <crate-name>` |
| rubygems.py           | RubyGems 包信息获取           | `get_package(gem)` | `python rubygems.py <gem-name>` |
| packagist.py          | Packagist 包信息获取          | `get_package(vendor/package)` | `python packagist.py <vendor/package>` |
| nuget.py              | NuGet 包信息获取              | `get_package(id)` | `python nuget.py <package-id>` |

> 7 个 ecosystem 子脚本输出统一 schema：`{name, description, latest_version, versions[], dependencies{}, download_url, license, homepage}`，便于 `dependency_analyzer.py` 通过 subprocess 调用并解析。

---

## Configuration

```json
{
  "db_path": "/tmp/ladybug_deps.db",
  "vulnerability_db": "https://api.osv.dev/v1",
  "ecosystems": ["pypi", "npm", "maven", "crates", "rubygems", "packagist", "nuget"],
  "output_format": "json",
  "max_cycles_detect": 100,
  "max_recommendations": 20
}
```

| 字段 | 类型 | 默认值 | 作用 |
|------|------|--------|------|
| `db_path` | str | `/tmp/ladybug_deps.db` | Ladybug GraphDB 文件路径，None 时自动创建临时目录 |
| `vulnerability_db` | str | `https://api.osv.dev/v1` | OSV 漏洞数据库 API 端点 |
| `ecosystems` | list | 7 个全量 | 启用的生态系统列表，未列出的 ecosystem 在 `query`/`search` 中会 `sys.exit(1)` |
| `output_format` | str | `json` | 报告输出格式（`json` / `html` / `pdf` / `sbom`，通过 `report --format` 指定） |
| `max_cycles_detect` | int | 100 | 循环依赖检测上限，超出后截断并提示调大 |
| `max_recommendations` | int | 20 | 版本推荐显示上限（`MAX_RECOMMENDATIONS_DISPLAY`） |

## Testing & Validation

测试 prompt 集见 `test-prompts.json`（3 个典型场景覆盖 query/security/多语言 analyze）。

单元测试（不入 git）：
- `scripts/tests/test_report_renderer.py` — HTML/PDF/JSON 渲染契约（11 个测试）
- `scripts/tests/test_health_scorer.py` — 5 维度评分逻辑（15 个测试）
- `scripts/tests/test_sbom_generator.py` — SPDX 2.3 schema 完整性（22 个测试）
- `scripts/tests/test_visualizer.py` — Mermaid 依赖树渲染 + 深度控制 + 循环检测（13 个测试）
- `scripts/tests/test_readme_generator.py` — README 生成 + ecosystem 分组 + fetcher 注入（13 个测试）
- `scripts/tests/test_impact_analyzer.py` — 冲突影响范围 + BFS 反向追溯 + 依赖链（10 个测试）
- `scripts/tests/test_simulator.py` — 升级影响模拟 + 风险等级 + 冲突检测 + fetcher 注入（18 个测试）
- `scripts/tests/test_vulnerability_prioritizer.py` — CVSS + exploit + business 加权排序（24 个测试）
- `scripts/tests/test_monitor.py` — cron 生成 + 历史对比 + 告警格式化 + webhook（27 个测试）

验证步骤：
1. `python -m py_compile scripts/*.py` — 18 个脚本语法检查（含 3 个新模块）
2. `python scripts/dependency_analyzer.py query numpy` — 验证 PyPI 查询链路
3. `python scripts/dependency_analyzer.py security requests` — 验证漏洞扫描链路
4. `python scripts/dependency_analyzer.py security requests --priority` — 验证漏洞优先级排序
5. `python scripts/dependency_analyzer.py report deps_data.json --format html -o r.html` — 验证 HTML 报告
6. `python scripts/dependency_analyzer.py report deps_data.json --format sbom -o r.spdx.json` — 验证 SBOM
7. `python scripts/dependency_analyzer.py health /path/to/project` — 验证健康度评分
8. `python scripts/dependency_analyzer.py analyze /path/to/project --visualize` — 验证 Mermaid 依赖树
9. `python scripts/dependency_analyzer.py analyze /path/to/project --impact` — 验证冲突影响分析
10. `python scripts/dependency_analyzer.py readme /path/to/project` — 验证依赖 README 生成
11. `python scripts/dependency_analyzer.py simulate requests 2.31.0` — 验证升级影响模拟
12. `python scripts/dependency_analyzer.py monitor /path/to/project --cron "0 9 * * *"` — 验证 cron 条目生成
13. `python -m pytest scripts/tests/ tests/ -v` — 跑全部单元测试（153 个 = 84 原 + 18 + 24 + 27 新）
14. 检查输出是否符合 `Output Example` 章节的 schema

## Dependencies

| 依赖 | 版本 | 用途 | 必需 |
|------|------|------|------|
| real_ladybug | latest | 图数据库（依赖关系存储） | ✅ 必需 |
| httpx | latest | HTTP 客户端（registry 查询） | ✅ 必需 |
| ua-generator | latest | 随机 User-Agent（防封禁） | ✅ 必需 |
| semver | latest | 语义化版本比较 | ✅ 必需 |
| Jinja2 | >=3.0 | HTML 模板渲染 | ✅ 必需（HTML/PDF 报告） |
| weasyprint | >=60 | HTML → PDF 转换 | ⚠️ 可选（仅 PDF 格式需要，未安装时显式报错） |
| tomli / tomllib | latest | TOML 解析（pyproject.toml） | ✅ 必需（Python < 3.11 用 tomli） |

## 异常处理

| 场景 | 触发条件 | 一线修复 | 仍失败兜底 |
|------|---------|---------|-----------|
| 项目无任何已知配置文件 | 7 类配置文件均未检测到 | 列出支持的 7 类文件让用户补充路径 | 终止 analyze，引导改用 `query`/`search` 子命令 |
| 网络不可用导致包信息查询失败 | HTTP 请求超时或 DNS 失败 | 重试 3 次（指数退避，见 `utils.py:MAX_RETRIES`） | 标注"离线模式"，跳过在线漏洞扫描并显式告知 |
| OSV 漏洞数据库无响应 | API 返回 5xx 或超时 | 重试 1 次 | 跳过漏洞扫描并明确告知用户"未扫描，不等于无漏洞" |
| 循环依赖检测超出 `max_cycles_detect` | 检测到的循环数 > 配置上限 | 截断并报告前 N 个循环 | 提示用户调大 `max_cycles_detect` 配置值 |
| Ladybug GraphDB 初始化失败 | DB 文件无写权限或路径错误 | 提示检查 `db_path` 权限 | 终止分析，不降级到无图分析（会丢失冲突检测能力） |
| 包版本不存在于远程 registry | registry 404 | 检查包名拼写 | 标注"本地版本未发布"，不假设版本号 |
| 配置文件解析错误（语法） | TOML/JSON/YAML 解析报错 | 报错位置 + 行号 | 询问用户是否修复，不静默跳过 |
| 多生态系统配置文件并存 | 同目录检测到 ≥2 类配置文件 | 🔴 CHECKPOINT：列出检测到的生态系统，询问扫描范围 | 用户未选择则按全部处理 |
| Maven `pom.xml`/`Cargo.toml` 等命中但无 parser | detect 识别但 parsers 表无对应实现 | 显式提示"自动解析器暂未实现" | 引导改用 `query -e <ecosystem>` 子命令 |
| weasyprint 未安装但请求 PDF 格式 | `report --format pdf` 时 `import weasyprint` 失败 | 显式抛 `RuntimeError` 含安装命令 `pip install weasyprint` | 不降级为 HTML，让用户显式选择 `--format html` |
