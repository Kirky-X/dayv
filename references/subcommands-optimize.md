# optimize · 依赖配置优化

> 优化项目依赖配置：去重子依赖 + 删除冗余传递依赖 + 识别未使用依赖。目的：减小配置文件大小、避免二进制变大。命令速查见 [subcommands.md](./subcommands.md)。

## 三类检测

| 检测 | 字段 | 逻辑 | 价值 |
|------|------|------|------|
| `dedupe` | duplicates | 同 name 多 entry（重复声明子依赖） | 减小配置文件大小 |
| `redundant` | redundant | 能被其他显式声明包自动引入的传递依赖 | 删冗余手动声明 |
| `unused` | unused | 声明了但代码没 import 的依赖 | 避免二进制变大 |

## 用法

```bash
# 全部检测（默认）
python scripts/dependency_analyzer.py optimize /path/to/project

# 仅指定检测（可多次 --check）
python scripts/dependency_analyzer.py optimize /path/to/project --check dedupe --check unused

# redundant deep 模式（查 registry 准确判断，需网络）
python scripts/dependency_analyzer.py optimize /path/to/project --deep

# 输出 JSON 结果到文件
python scripts/dependency_analyzer.py optimize /path/to/project -o optimize.json
```

## redundant 模式

| 模式 | 触发 | 准确性 | 说明 |
|------|------|--------|------|
| quick（默认） | 未加 `--deep` | 有限（仅基于 edges） | 无网络，快速；显式提示"建议 --deep 确认" |
| deep | `--deep` | 高（查 registry） | 需网络；用 EcosystemFetcher 查每个包的 dependencies |

> quick 模式不静默成功——输出显式标注"redundant 为 quick 模式，准确性有限"。

## unused 检测的 ecosystem 支持

| ecosystem | 扫描文件 | import 模式 | 准确性 |
|-----------|---------|------------|--------|
| pypi | `.py` | `import X` / `from X import` | ✅ 精确（连字符→下划线归一化） |
| npm | `.js/.ts/.jsx/.tsx/.mjs/.cjs` | `require('X')` / `from 'X'` / `import 'X'` | ✅ 精确（含 @scope/pkg；跳过相对路径） |
| crates | `.rs` | `use X::` / `extern crate X` | ✅ 精确 |
| rubygems | `.rb` | `require 'X'` | ✅ 精确 |
| maven | `.java` | `import X.Y.Z` | ⚠️ 类全名无法映射 groupId:artifactId |
| packagist | `.php` | `use X\Y\Z` | ⚠️ 命名空间无法映射 composer 包名 |
| nuget | `.cs` | `using X.Y.Z` | ⚠️ 命名空间无法映射 NuGet 包名 |

> 开发工具白名单（pytest/black/eslint/typescript 等）声明但不需要 import，自动排除。
> 跳过目录：node_modules/venv/__pycache__/target/build/dist/.git/vendor 等。

## 输出 schema

```json
{
  "project_path": "/path/to/project",
  "ecosystem": "pypi",
  "total_packages": 12,
  "checks_run": ["dedupe", "redundant", "unused"],
  "redundant_mode": "quick",
  "duplicates": [
    {"name": "numpy", "count": 2,
     "entries": [{"version": "1.21", "ecosystem": "pypi", "is_root": false}],
     "suggestion": "统一 numpy 版本声明，仅保留一个（建议保留最新稳定版 1.23）"}
  ],
  "redundant": [
    {"package": "urllib3", "reason": "是 requests 的传递依赖，requests 会自动引入它",
     "引入方": ["requests"]}
  ],
  "unused": {
    "declared_count": 12, "used_count": 10, "unused_count": 2,
    "used": ["flask", "requests"],
    "unused": ["unused-pkg-1", "unused-pkg-2"],
    "note": ""
  }
}
```

## 复用函数（`dependency_optimizer.py`）

| 函数 | 用途 |
|------|------|
| `find_duplicates(deps_data)` | 检测重复声明 |
| `find_redundant(deps_data, fetcher=None)` | 检测冗余传递依赖（quick/deep） |
| `find_unused(project_path, deps_data, ecosystem)` | 扫描代码 import 对比声明 |
| `optimize(project_path, deps_data, ecosystem, checks=None, fetcher=None)` | 主入口 |
| `format_optimize_report(result)` | 格式化可读报告 |
