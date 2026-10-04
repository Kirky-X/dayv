# Core Features 详解

> 依赖分析器 13 个核心功能的详细说明。命令速查见 [subcommands.md](./subcommands.md)。

## 1. 依赖关系图分析

基于 Ladybug 图数据库构建依赖关系图：
- `Package` 节点：包名、版本、生态系统、描述、许可证等
- `DependsOn` 关系：依赖约束、依赖类型
- `ConflictsWith` 关系：冲突原因、严重级别
- `Vulnerability` 节点：CVE ID、受影响版本、修复版本

## 2. 版本冲突检测

自动检测依赖冲突：
- 版本约束不满足
- 循环依赖
- 版本不兼容

输出冲突信息包括：
- 冲突包名
- 冲突来源（哪些包依赖了冲突版本）
- 冲突类型和严重级别
- 解决建议

## 3. 安全漏洞扫描

基于漏洞数据库检查：
- CVE ID 和严重级别
- 受影响版本范围
- 修复版本
- 漏洞描述和参考链接

## 4. 版本优化推荐

智能推荐最优版本：
- 满足所有版本约束
- 避免已知漏洞
- 尽量使用最新稳定版
- 提供更新路径和迁移步骤

## 5. HTML/PDF 报告输出

`report --format html|pdf` 生成可视化报告：
- **HTML**: 基于 Jinja2 模板，含 6 大章节（项目概览/依赖列表/冲突检测/漏洞检测/许可证合规/版本推荐），表格支持点击表头排序，UTF-8 编码支持中文，自动转义防 XSS
- **PDF**: 由 HTML 经 weasyprint 转换，需安装 `pip install weasyprint`（系统依赖：`apt install libpango-1.0-0 libpangoft2-1.0-0`）；未安装时显式抛 `RuntimeError` 提示安装，不静默失败
- **JSON** (默认): 与 `export_report_json` schema 完全一致，向后兼容
- 复用 `report_renderer.render_report(report_dict, output_path, fmt)` 统一入口

## 6. SBOM 生成 (SPDX 2.3)

`report --format sbom` 生成软件物料清单：
- **标准**: SPDX 2.3 JSON（国际标准，参考 https://spdx.github.io/spdx-spec/）
- **顶层字段**: SPDXVersion / DataLicense(CC0-1.0) / SPDXID / DocumentName / DocumentNamespace(含 UUID 保证唯一) / CreationInfo / Packages / Relationships
- **Package 字段**: Name / SPDXID / VersionInfo / DownloadLocation(按 ecosystem 拼 registry URL) / FilesAnalyzed(false) / LicenseConcluded / Supplier
- **Relationships**: DESCRIBES(文档→根包) + DEPENDS_ON(来自 edges)
- **输出文件**: 默认 `{project_name}-sbom.spdx.json`
- 复用 `sbom_generator.write_sbom(packages, edges, project_name, output_path)`

## 7. 依赖健康度评分

`health <project_path>` 综合评估依赖健康度：
- **总分**: 0-100，加权平均 5 个维度
- **维度与权重**:
  | 维度 | 权重 | 评分逻辑 |
  |------|------|----------|
  | version_freshness 版本新旧度 | 0.20 | `100 * (1 - update_paths/total_packages)` |
  | vulnerability_status 漏洞状态 | 0.30 | `100 - Σ(漏洞扣分)`，critical=40/high=25/medium=20/low=5 |
  | maintenance_status 维护状态 | 0.15 | base=50，有更新活动+25，无漏洞+25 |
  | dependency_stability 依赖稳定性 | 0.20 | `100 - conflicts*25` |
  | license_compliance 许可证合规性 | 0.15 | 默认 75（无 license 数据时中性分） |
- **阈值**: `>=70` healthy / `50-69` warning / `<50` danger
- **输出**: 总分 + 5 维度 ASCII 进度条 + 改进建议（针对最低分维度）+ Mermaid 雷达图
- 复用 `health_scorer.score_health(report_dict)` + `health_scorer.render_radar_mermaid(result)`

## 8. Mermaid 依赖树可视化

`analyze --visualize [--depth N]` 渲染依赖树为 Mermaid flowchart：
- **方向**: TD（top-down）
- **节点**: `P0["name@version"]`（节点 ID 用 P{index} 序号分配，避免重名 + Mermaid 非法字符）
- **边**: `P0 --> P1` 表示 A 依赖 B
- **深度控制**: `--depth N`（默认 3），从根出发的依赖层数；超出深度的节点不渲染
- **循环依赖检测**: 检测到环时标注 `%% CIRCULAR DETECTED: a --> b` 并停止该分支（不无限循环）
- **根节点识别**: 优先 `is_root=True`，否则入度为 0 的包，否则全部当根
- **输出**: stdout（默认）或 `-o file.mmd` 写文件
- 复用 `visualizer.render_mermaid_tree(deps_data, depth=3)`

## 9. 冲突影响范围分析

`analyze --impact` 分析版本冲突的受影响范围：
- **输入**: 依赖图 + `detect_conflicts()` 输出的冲突列表
- **输出**: 每个冲突的影响范围 dict
  ```
  {
    conflict_package: str,            # 冲突包名
    required_versions: list[dict],    # 版本要求 [{package, constraint}]
    affected_packages: list[str],     # 反向追溯到的所有依赖者（不含冲突包本身）
    dependency_chains: list[list[str]]# 从根到冲突包的所有路径
  }
  ```
- **BFS 反向遍历**: 从冲突包出发，沿反向边找出所有传递依赖它的包
- **DFS 路径搜索**: 找从根到冲突包的所有路径（带环检测，避免无限循环）
- **防爆炸**: `MAX_AFFECTED_PACKAGES=1000` / `MAX_CHAINS=50` / `MAX_CHAIN_LENGTH=50`
- **输出格式**: 文本（默认，含受影响包列表 + 依赖链路径）或 `-o file.json`（JSON）
- 复用 `impact_analyzer.analyze_conflict_impact(deps_data, conflicts)` + `impact_analyzer.format_impact_report(impacts)`

## 10. 项目依赖 README 生成

`readme <project_path>` 生成可插入项目 README 的"依赖说明"章节：
- **章节结构**:
  ```markdown
  ## 依赖说明

  ### PyPI (3 个)

  | 包名 | 版本 | 用途 | 许可证 |
  |------|------|------|--------|
  | requests | 2.28.0 | HTTP library | Apache-2.0 |

  ### npm (2 个)
  ...
  ```
- **按 ecosystem 分组**: 7 个已知 ecosystem 按固定顺序（PyPI/npm/Maven/crates/RubyGems/Packagist/NuGet），未知 ecosystem 排最后
- **用途/许可证查询**: 通过 `EcosystemFetcher` 用 subprocess 调用对应 ecosystem 脚本（`pypi.py`/`npm.py`/...）获取 `description` 和 `license`
- **容错**: 查询失败/超时/解析错误时显示占位符 `-`，不崩溃（Rule 12 显性化：不静默吞错）
- **根包排除**: `is_root=True` 的包不进入依赖表格（项目本身不是依赖）
- **缓存**: `EcosystemFetcher` 内置 dict 缓存，避免重复查询同一包
- **输出**: stdout（默认）或 `-o DEPS.md` 写文件
- 复用 `readme_generator.generate_dependency_readme(deps_data, fetcher=...)`

## 11. 升级影响模拟 (dry-run)

`simulate <package> <target_version> [--project <path>]` 模拟升级某依赖到目标版本后的影响，不实际升级：
- **风险等级判定**:
  | 变化类型 | 风险等级 |
  |---------|---------|
  | major 升级 (X.y.z → X+1.0.0) | high |
  | minor 升级 (x.Y.z → x.Y+1.0) | medium |
  | patch 升级 (x.y.Z → x.y.Z+1) | low |
  | 降级 | high |
  | 版本解析失败 | high（保守处理） |
- **新增/移除依赖**: 对比 target_version 的依赖列表（通过 ecosystem 脚本查询）与 deps_data 中的现有依赖
- **冲突检测**: 新增依赖的版本约束与现有依赖图中的版本不兼容时报告冲突
- **回滚建议**: 按 ecosystem 生成（pypi: `git checkout requirements.txt` / npm: `git checkout package.json && npm install` / ...）
- **输出 schema**:
  ```json
  {
    "package": "requests", "current_version": "2.28.0", "target_version": "3.0.0",
    "risk_level": "high",
    "added_dependencies": [{"name": "urllib3", "constraint": ">=2.0.0"}],
    "removed_dependencies": [],
    "conflicts": [{"package": "urllib3", "reason": "目标版本需要 >=2.0.0，现有版本 1.26.0 不满足",
                   "existing_version": "1.26.0", "required_constraint": ">=2.0.0"}],
    "rollback_suggestion": "git checkout requirements.txt  # 或 pip install requests==2.28.0"
  }
  ```
- **--project 可选**: 无项目路径时仅基于版本号判定风险；有项目路径时分析现有依赖图
- 复用 `simulator.simulate_upgrade(deps_data, package, target_version, ecosystem, fetcher=None)` + `simulator.format_simulation_report(result)`

## 12. 漏洞修复优先级排序

`security <package> --priority` 对检测到的漏洞按修复优先级排序：
- **三维度加权打分**:
  | 维度 | 权重 | 评分逻辑 |
  |------|------|----------|
  | CVSS 严重度 | 0.5 | Critical=4 / High=3 / Medium=2 / Low=1 |
  | 利用难度 | 0.3 | 有公开 exploit/PoC=2 / 无=1 |
  | 业务影响 | 0.2 | 根依赖=3 / 直接依赖=2 / 传递依赖=1 |
- **优先级总分** = CVSS × 0.5 + exploit × 0.3 + business × 0.2
- **排序**: 按 priority_score 降序，priority_rank 从 1 开始
- **exploit 检测**: `vuln["has_exploit"]=True` 或 `vuln["references"]` 含 "exploit"/"poc" 关键词
- **业务影响判定**: 从 deps_data 中查找包层级（is_root / 被根直接依赖 / 传递依赖）
- **修复建议**: 有 fixed_version 时建议升级；无 fixed_version 时明确提示"暂无已知修复版本"（不静默）
- **输出**: 序号 + CVE ID + 包名@版本 + 严重度 + 优先级分 + 修复建议
- 复用 `vulnerability_prioritizer.prioritize_vulnerabilities(vulns, deps_data)` + `vulnerability_prioritizer.format_priority_report(prioritized)`

## 13. 漏洞持续监控

`monitor <project_path> [--cron <expr>] [--webhook <url>]` 定时扫描项目漏洞状态：
- **扫描**: 调用 `DependencyAnalyzer.assess_security()` 获取当前漏洞列表
- **历史对比**: 与 `~/.dayv/monitor_history.json` 中最近一次扫描对比，找出新增漏洞（按 cve_id + package 唯一）
- **告警**: 检测到新漏洞时输出告警文本 + 可选 webhook POST
  ```
  [DAYV ALERT] 检测到 3 个新漏洞
  - CVE-2024-1234 (Critical) on requests@2.28.0
  - CVE-2024-5678 (High) on urllib3@1.26.12
  ```
- **webhook**: `--webhook <url>` POST JSON payload（含 alert_type/count/vulnerabilities/message），成功返回 True / 失败返回 False（不抛异常）
- **cron 模式**: `--cron "0 9 * * *"` 输出 crontab 条目字符串（**不实际安装**，需手动 `crontab -e`）
  ```
  0 9 * * * cd /path/to/project && /usr/bin/env python3 .../dependency_analyzer.py monitor /path/to/project >> /tmp/dayv-monitor-<name>.log 2>&1
  ```
- **历史文件**: `~/.dayv/monitor_history.json`，保留最近 50 次扫描（`MAX_HISTORY_ENTRIES=50`），自动创建父目录
- **scanner 可注入**: `run_scan(project_path, scanner=None)` 支持注入 mock scanner 用于测试
- 复用 `monitor.run_scan()` / `monitor.compare_with_history()` / `monitor.send_alert()` / `monitor.generate_cron_entry()` / `monitor.format_alert()` / `monitor.save_scan_to_history()`
