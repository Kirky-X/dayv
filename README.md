# Dayv —— 多语言依赖分析引擎

[![GitHub Release](https://img.shields.io/github/v/release/Kirky-X/dayv?style=flat-square)](https://github.com/Kirky-X/dayv/releases)
[![GitHub License](https://img.shields.io/github/license/Kirky-X/dayv?style=flat-square)](LICENSE)

Dayv 是一个面向 AI agent 的依赖分析 skill，基于 **Ladybug 图数据库** 实现项目依赖关系可视化、版本冲突检测、安全漏洞扫描和版本优化推荐。覆盖 **7 个生态系统**：PyPI / npm / Maven / crates / RubyGems / Packagist / NuGet。

> Go 和 C/C++ 不在支持列表：Go 无中心 registry（依赖走 git modules），C/C++ 无单一中央仓库（vcpkg/conan 是分散式包管理器），与 dayv「中央包仓库查询」核心定位不匹配。

完整路由表与流程文档见 [SKILL.md](SKILL.md)。

## 功能特性

### 5 个子命令

| 子命令     | 说明                 | 使用场景                       |
| ---------- | -------------------- | ------------------------------ |
| `analyze`  | 分析项目依赖         | 分析项目的依赖树和依赖关系     |
| `query`    | 查询包依赖           | 查询某个包的上下游依赖         |
| `search`   | 搜索包               | 搜索包信息                     |
| `security` | 检查安全漏洞         | 扫描包的安全漏洞               |
| `report`   | 生成完整报告         | 生成 JSON 格式的完整分析报告   |

### 7 个支持的生态系统

| 生态系统   | 包管理器             | 配置文件                          |
| ---------- | -------------------- | --------------------------------- |
| Python     | PyPI / pip           | `pyproject.toml`, `requirements.txt` |
| Node.js    | npm / yarn           | `package.json`                    |
| Java       | Maven                | `pom.xml`                         |
| Rust       | Cargo                | `Cargo.toml`                      |
| Ruby       | RubyGems / bundler   | `Gemfile`                         |
| PHP        | Composer / Packagist | `composer.json`                   |
| .NET       | NuGet / dotnet CLI   | `*.csproj`, `*.fsproj`, `*.vbproj` |

### 核心能力

- **依赖关系图分析**：基于 Ladybug GraphDB 构建 `Package` / `DependsOn` / `ConflictsWith` / `Vulnerability` 节点和关系
- **版本冲突检测**：自动检测版本约束不满足、循环依赖、版本不兼容，输出冲突来源和解决建议
- **安全漏洞扫描**：基于 OSV 漏洞数据库，给出 CVE ID / 严重级别 / 受影响版本 / 修复版本
- **版本优化推荐**：在满足所有约束 + 避免已知漏洞 + 尽量使用最新稳定版之间求最优解

## 安装

### 方式一：通过 `skills` 包安装（推荐）

需 [Node.js](https://nodejs.org/) 18+ 和 `skills` npm 包（v1.5.12+）。

```bash
# 安装到 Claude Code
npx skills add https://github.com/Kirky-X/dayv.git --agent claude-code -y

# 等价简写（owner/repo）
npx skills add Kirky-X/dayv --agent claude-code -y

# 安装到 Codex
npx skills add Kirky-X/dayv --agent codex -y

# 列出仓库中可被发现的所有 skills（不安装）
npx skills add https://github.com/Kirky-X/dayv.git --list
```

安装后 skill 文件位于对应 agent 的 skills 目录（如 `.claude/skills/dayv/`）。

### 方式二：传统 git clone

```bash
git clone https://github.com/Kirky-X/dayv.git
# 将 SKILL.md + scripts/ 链接或复制到 agent skills 目录
# 各 runtime 的 skills 目录路径示例（任选其一）：
#   Claude Code:  ~/.claude/skills/dayv/
#   Codex:        ~/.codex/skills/dayv/
#   Cursor:       ~/.cursor/skills/dayv/
```

## 使用示例

Dayv 作为 skill 被 agent 加载后，通过自然语言意图触发，无需显式命令。触发词包括「dependency」「依赖树」「版本冲突」「安全漏洞」「dependency tree」「version conflict」「security vulnerability」「package info」等。

### 分析项目依赖（自动检测配置文件类型）

```bash
# 进入项目目录
cd /path/to/project

# 自动识别 pyproject.toml / package.json / Cargo.toml / pom.xml / Gemfile / composer.json / .csproj
python scripts/dependency_analyzer.py analyze .
  # 可选 flag: --conflicts | --recommend | --security | --updates | --report -o <file>
```

### 查询包的依赖关系

```bash
# 默认 ecosystem=pypi
python scripts/dependency_analyzer.py query numpy
python scripts/dependency_analyzer.py query react -e npm
python scripts/dependency_analyzer.py query org.springframework.boot:spring-boot -e maven
python scripts/dependency_analyzer.py query serde -e crates
python scripts/dependency_analyzer.py query rails -e rubygems
python scripts/dependency_analyzer.py query monolog/monolog -e packagist
python scripts/dependency_analyzer.py query Newtonsoft.Json -e nuget
```

### 搜索包

```bash
python scripts/dependency_analyzer.py search "web framework"
python scripts/dependency_analyzer.py search "logging" -e npm
```

### 检查安全漏洞（先查真实最新版本，避免 false positive）

```bash
python scripts/dependency_analyzer.py security requests
```

### 从 deps_data.json 生成完整报告

```bash
python scripts/dependency_analyzer.py report deps_data.json -o report.json
# deps_data.json schema:
# {"packages": [{"name", "version", "ecosystem", "is_root"}],
#  "edges":   [{"source", "target", "constraint"}]}
```

## 输出示例

### 冲突检测

```text
⚠️ Conflict Detected: numpy
  Required by: pandas>=2.0 (numpy>=1.21), scipy>=1.10 (numpy>=1.23)
  Conflict type: version_mismatch   Severity: high
  Suggestion: 统一 numpy 的版本约束
```

### 安全漏洞检测

```text
🔴 Vulnerability: requests@2.25.0
  CVE ID: CVE-2023-32681   Severity: HIGH
  Fixed version: 2.31.0
  Description: Unintended leak of Proxy-Authorization header
```

### report.json schema

```json
{
  "timestamp": 1730000000.0,
  "root_package": "my-project",
  "summary": {"total_packages": 12, "total_dependencies": 30, "conflicts": 1, "vulnerabilities": 2, "update_paths": 1},
  "conflicts":        [{"package": "numpy", "conflict_type": "version_mismatch", "severity": "high", "required_by": [...], "suggestion": "..."}],
  "vulnerabilities":  [{"cve_id": "CVE-2023-32681", "package": "requests", "version": "2.25.0", "severity": "high", "fixed_version": "2.31.0"}],
  "update_paths":     [{"package": "requests", "current_version": "2.25.0", "target_version": "2.31.0", "steps": [...]}],
  "recommendations":  ["发现 1 个依赖冲突，建议统一版本约束"]
}
```

## 脚本

| 脚本                  | 用途                          | 入口                                       |
| --------------------- | ----------------------------- | ------------------------------------------ |
| `dependency_analyzer.py` | 主分析引擎                 | `python dependency_analyzer.py <subcommand> [args]` |
| `utils.py`            | 版本比较和约束检查工具        | `from utils import check_version_constraint, compare_versions, sort_versions` |
| `pypi.py`             | PyPI 包信息获取               | `python pypi.py <package>` / `--search <keyword>` |
| `npm.py`              | npm 包信息获取                | `python npm.py <package>` / `--search <keyword>` |
| `maven.py`            | Maven 包信息获取              | `python maven.py <groupId>:<artifactId>`   |
| `crates.py`           | crates.io 包信息获取          | `python crates.py <crate-name>`            |
| `rubygems.py`         | RubyGems 包信息获取           | `python rubygems.py <gem-name>`            |
| `packagist.py`        | Packagist 包信息获取          | `python packagist.py <vendor/package>`     |
| `nuget.py`            | NuGet 包信息获取              | `python nuget.py <package-id>`             |

> 7 个 ecosystem 子脚本输出统一 schema：`{name, description, latest_version, versions[], dependencies{}, download_url, license, homepage}`，便于 `dependency_analyzer.py` 通过 subprocess 调用并解析。

## 配置

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

| 字段                  | 类型 | 默认值                    | 作用                                          |
| --------------------- | ---- | ------------------------- | --------------------------------------------- |
| `db_path`             | str  | `/tmp/ladybug_deps.db`    | Ladybug GraphDB 文件路径，None 时自动创建临时目录 |
| `vulnerability_db`    | str  | `https://api.osv.dev/v1`  | OSV 漏洞数据库 API 端点                       |
| `ecosystems`          | list | 7 个全量                  | 启用的生态系统列表，未列出的 ecosystem 在 `query`/`search` 中会 `sys.exit(1)` |
| `output_format`       | str  | `json`                    | 报告输出格式（当前仅支持 `json`）             |
| `max_cycles_detect`   | int  | 100                       | 循环依赖检测上限，超出后截断并提示调大        |
| `max_recommendations` | int  | 20                        | 版本推荐显示上限                              |

## 反模式（禁止做）

### 数据正确性红线

- ❌ 用假版本号跑 `security` 子命令（误报漏洞，必须先查真实最新版本）
- ❌ 假设最新版本一定满足所有约束（推荐前必须 `check_version_constraint` 验证）
- ❌ 静默吞掉解析错误继续跑（解析失败必须报错位置 + 行号）
- ❌ 把 OSV 无响应当作"无漏洞"（必须显式告知"未扫描"）
- ❌ 假设 `parse_dependencies` 能解析所有 7 类文件（Maven/Cargo/Gemfile 等会 `sys.exit(1)`）

### 范围红线

- ❌ 不要为 Go 项目调用本 skill（无中央 registry）
- ❌ 不要为 C/C++ 项目调用本 skill（vcpkg/conan 是分散式包管理器）
- ❌ 不要扫描 `node_modules`/`venv`/`target` 等构建产物目录

## 外部资源

- [OSV Vulnerability Database](https://osv.dev/)
- [PyPI](https://pypi.org/) / [npm](https://www.npmjs.com/) / [Maven Central](https://central.sonatype.com/) / [crates.io](https://crates.io/) / [RubyGems](https://rubygems.org/) / [Packagist](https://packagist.org/) / [NuGet](https://www.nuget.org/)

## 许可证

MIT
