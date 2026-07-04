---
name: dependency
description: "依赖分析引擎。 When: 用户请求分析项目依赖、检测版本冲突、查询包依赖关系、检查安全漏洞或生成依赖报告时；触发词：dependency、依赖树、版本冲突、安全漏洞、package.json、pyproject.toml、Cargo.toml、pom.xml"
argument-hint: "<analyze|query|search|security|report> [options]"
---

# Dependency Analysis Skill — 依赖分析引擎

> **基于 Ladybug 图数据库的智能依赖关系分析工具**

## Overview

统一的依赖分析技能，基于图数据库实现依赖关系可视化、冲突检测、安全漏洞扫描和版本优化推荐。

## Subcommands

| Subcommand | 说明                   | 使用场景                       |
| ---------- | ---------------------- | ------------------------------ |
| `analyze`  | 分析项目依赖           | 分析项目的依赖树和依赖关系     |
| `query`    | 查询包依赖             | 查询某个包的上下游依赖         |
| `search`   | 搜索包                 | 搜索包信息                     |
| `security` | 检查安全漏洞           | 扫描包的安全漏洞               |
| `report`   | 生成完整报告           | 生成 JSON 格式的完整分析报告   |

---

## Supported Ecosystems

| 生态系统   | 包管理器     | 配置文件             |
| ---------- | ------------ | -------------------- |
| Python     | PyPI / pip   | pyproject.toml, requirements.txt |
| Node.js    | npm / yarn   | package.json         |
| Java       | Maven        | pom.xml              |
| Rust       | Cargo        | Cargo.toml           |
| Ruby       | RubyGems / bundler | Gemfile         |
| PHP        | Composer / Packagist | composer.json  |
| .NET       | NuGet / dotnet CLI  | *.csproj, *.fsproj, *.vbproj |

> Go 和 C/C++ 不在支持列表：Go 无中心 registry（依赖走 git modules，发布走 GitHub Release）；C/C++ 无单一中央仓库（vcpkg/conan 是分散式包管理器）。两者与 dayv「中央包仓库查询」核心定位不匹配。

---

## Quick Start

```bash
# 分析项目依赖（自动检测配置文件类型）
python scripts/dependency_analyzer.py analyze /path/to/project

# 查询包的依赖关系
python scripts/dependency_analyzer.py query numpy

# 搜索包
python scripts/dependency_analyzer.py search "web framework"

# 检查安全漏洞
python scripts/dependency_analyzer.py security requests

# 生成完整报告（JSON 格式）
python scripts/dependency_analyzer.py report /path/to/project -o report.json
```

---

## Core Features

### 1. 依赖关系图分析

基于 Ladybug 图数据库构建依赖关系图：
- `Package` 节点：包名、版本、生态系统、描述、许可证等
- `DependsOn` 关系：依赖约束、依赖类型
- `ConflictsWith` 关系：冲突原因、严重级别
- `Vulnerability` 节点：CVE ID、受影响版本、修复版本

### 2. 版本冲突检测

自动检测依赖冲突：
- 版本约束不满足
- 循环依赖
- 版本不兼容

输出冲突信息包括：
- 冲突包名
- 冲突来源（哪些包依赖了冲突版本）
- 冲突类型和严重级别
- 解决建议

### 3. 安全漏洞扫描

基于漏洞数据库检查：
- CVE ID 和严重级别
- 受影响版本范围
- 修复版本
- 漏洞描述和参考链接

### 4. 版本优化推荐

智能推荐最优版本：
- 满足所有版本约束
- 避免已知漏洞
- 尽量使用最新稳定版
- 提供更新路径和迁移步骤

---

## Analysis Workflow

```
项目路径
    │
    ▼
1. 检测依赖配置文件 (pyproject.toml / package.json / Cargo.toml / pom.xml)
   - **Checkpoint**: 检测到多个生态系统配置文件 → 询问用户扫描范围（全部 / 单个）
    │
    ▼
2. 解析依赖列表
    │
    ▼
3. 构建依赖关系图 (Ladybug GraphDB)
    │
    ▼
4. 检测冲突
   - 版本约束冲突
   - 循环依赖
   - **Checkpoint**: 发现 HIGH 严重级别冲突 → 暂停并报告，询问是否继续完整扫描
    │
    ▼
5. 安全漏洞扫描
    │
    ▼
6. 版本推荐
   - **Checkpoint**: 推荐升级前确认目标版本满足所有约束，不假设最新版即可
    │
    ▼
7. 生成报告 (JSON / 可视化)
```

---

## Output Example

### 冲突检测结果

```
⚠️ Conflict Detected: numpy
  Required by:
    - pandas>=2.0 requires numpy>=1.21
    - scipy>=1.10 requires numpy>=1.23
  Conflict type: version_constraint
  Severity: medium
  Suggestion: Upgrade numpy to >=1.23 to satisfy both constraints
```

### 安全漏洞检测结果

```
🔴 Vulnerability: requests@2.25.0
  CVE ID: CVE-2023-32681
  Severity: HIGH
  Description: Unintended leak of Proxy-Authorization header
  Fixed version: 2.31.0
  References: https://nvd.nist.gov/vuln/detail/CVE-2023-32681
```

---

## Scripts

| Script                | Purpose                       |
| --------------------- | ----------------------------- |
| dependency_analyzer.py| 主分析引擎                    |
| utils.py              | 版本比较和约束检查工具        |
| pypi.py               | PyPI 包信息获取               |
| npm.py                | npm 包信息获取                |
| maven.py              | Maven 包信息获取              |
| crates.py             | crates.io 包信息获取          |
| rubygems.py           | RubyGems 包信息获取           |
| packagist.py          | Packagist 包信息获取          |
| nuget.py              | NuGet 包信息获取              |

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

---

## Integration

| Integrated Skill | Workflow                                    |
| ---------------- | ------------------------------------------- |
| build            | 依赖分析 → 版本更新 → 构建                   |
| review           | 依赖冲突 → 安全漏洞 → 代码审查                |
| security-expert  | 漏洞扫描 → 安全评估 → 修复建议                |

---

## External Resources

- [OSV Vulnerability Database](https://osv.dev/)
- [PyPI](https://pypi.org/)
- [npm](https://www.npmjs.com/)
- [Maven Central](https://central.sonatype.com/)
- [crates.io](https://crates.io/)
- [RubyGems](https://rubygems.org/)
- [Packagist](https://packagist.org/)
- [NuGet](https://www.nuget.org/)

## 异常处理

| 场景 | 触发条件 | Fallback 路径 |
|------|---------|--------------|
| 项目无任何已知配置文件 | 7 类配置文件均未检测到 | 报告"未检测到依赖配置"，列出支持的 7 类文件（pyproject.toml/requirements.txt/setup.py、package.json、pom.xml/build.gradle、Cargo.toml、Gemfile、composer.json、*.csproj/*.fsproj/*.vbproj） |
| 网络不可用导致包信息查询失败 | HTTP 请求超时或 DNS 失败 | 使用本地缓存数据，标注"离线模式"，跳过在线漏洞扫描 |
| OSV 漏洞数据库无响应 | API 返回 5xx 或超时 | 跳过漏洞扫描并明确告知用户，不假设无漏洞 |
| 循环依赖检测超出 `max_cycles_detect` | 检测到的循环数 > 配置上限 | 截断并报告前 N 个循环，提示调大配置 |
| Ladybug GraphDB 初始化失败 | DB 文件无写权限或路径错误 | 报错并提示检查 `db_path` 权限，不降级到无图分析 |
| 包版本不存在于远程 registry | registry 404 | 标注"本地版本未发布"，不假设版本号 |
| 配置文件解析错误（语法） | TOML/JSON/YAML 解析报错 | 报错位置 + 行号，询问用户是否修复 |