# Anti-patterns

> 红灯清单（数据正确性/范围/输出/并发限流）。从 SKILL.md 外移。

## Anti-patterns / 红灯清单（不要做什么）

> 以下行为会破坏分析正确性或导致 false positive，**严禁**：

### 数据正确性红线

| 红灯 | 后果 | 正确做法 |
|------|------|---------|
| 🚫 用假版本号跑 `security` 子命令 | 误报漏洞（如把已修复版本仍判为受影响） | 必须先调 `pypi.py` 查真实最新版本，查不到则**终止**并告知用户 |
| 🚫 假设最新版本一定满足所有约束 | 推荐版本与现有依赖冲突 | 推荐前必须 `check_version_constraint` 验证所有约束 |
| 🚫 静默吞掉解析错误继续跑 | 报告看似完整实则漏掉依赖 | 解析失败必须报错位置 + 行号，让用户决策 |
| 🚫 把 OSV 无响应当作"无漏洞" | 用户误以为安全 | 必须显式告知"未扫描"，不能默认 success |
| 🚫 假设 `parse_dependencies` 能完整解析所有 7 类 manifest | Maven/Cargo/Gemfile 等走最小解析，约束是下界近似而非精确版本 | 优先 lockfile（精确版本）；解析能力用 `analyze --list-parsers` 自省 |

### 范围红线

| 红灯 | 为什么禁止 |
|------|-----------|
| 🚫 不要为 Go 项目调用本 skill | Go 无中央 registry，依赖走 git modules，与 dayv 核心定位不匹配 |
| 🚫 不要为 C/C++ 项目调用本 skill | vcpkg/conan 是分散式包管理器，无单一查询入口 |
| 🚫 不要扫描 `node_modules`/`venv`/`target` 等构建产物目录 | 会导致依赖图爆炸，重复包节点 |

### 输出红线

| 红灯 | 正确做法 |
|------|---------|
| 🚫 不要把 `0.0.0` 当作真实版本输出给用户 | 解析失败时显式标注"版本未识别"，不输出占位值 |
| 🚫 不要在 `report` 子命令中省略 `vulnerabilities` 字段 | 即使为空也要输出 `[]`，保持 JSON schema 稳定 |
| 🚫 不要用 `print` 替代 `logger` 输出诊断信息 | 用户管道 `python dependency_analyzer.py ... | jq` 会被污染 |

### 并发与限流红线

| 红灯 | 正确做法 |
|------|---------|
| 🚫 不要并发请求同一 registry | `utils.RequestClient` 已内置 `_random_delay`，串行调用 |
