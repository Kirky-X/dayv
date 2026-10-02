# dayv 规则引擎场景配方（rules-recipes）

> 来源：调研建议 R11（对标 [dependency-cruiser](https://github.com/sverweij/dependency-cruiser) 的
> forbidden/allowed/required 规则设计，吸收语义而非代码）。
> 来源: 自研 ｜ 许可: MIT ｜ 核验日期: 2026-10-03

规则文件默认放 `.dayv/rules.json`，经 `analyze-data --rules <file>` 消费；
也可独立运行：`python scripts/rule_engine.py rules.json deps_data.json`（存在
error 级违规退出 1，可直接进 CI 门禁）。

## 规则 schema 速查

```json
{
  "extends": "dayv:recommended",
  "rules": [
    {
      "name": "规则名",
      "type": "forbidden",      // forbidden | allowed | required
      "severity": "error",      // error | warn | info | ignore
      "to": "^regex$",          // 可选：被依赖包名正则（大小写不敏感）
      "from": "^regex$",        // 可选：依赖方包名正则（边级规则）
      "license": "^GPL",        // 可选：许可证正则（缺失许可证不判定）
      "group": "dev",           // 可选：依赖组（npm 的 dev/dependencies 等）
      "deprecated": true,       // 可选：弃用标记（npm deprecated / crates yanked）
      "message": "自定义说明"     // 可选：违规时展示
    }
  ]
}
```

## 配方 1：生产依赖图禁含 dev 依赖组

```json
{"rules": [{"name": "生产禁 dev", "type": "forbidden", "severity": "error",
            "group": "dev"}]}
```

适用 `package.json`（devDependencies）与 `Cargo.toml`（dev-dependencies）解析结果。
`analyze-data` 走 deps_data 时，组信息来自解析器的 `group` 字段。

## 配方 2：禁 GPL 系传染性许可证

```json
{"rules": [{"name": "禁 GPL 系", "type": "forbidden", "severity": "error",
            "license": "^(GPL|AGPL|SSPL)"}]}
```

注意：许可证未采集（空）的包**不判定**——"无法校验 ≠ 违规"；需要对 UNKNOWN
显式把关时改用 `report --allowed-licenses`（UNKNOWN 单列语义）。

## 配方 3：弃用包防新增

```json
{"extends": "dayv:recommended"}
```

预设内置三条：生产禁 dev 组（warn）/ 禁 GPL 系（error）/ 弃用包防新增（warn，
数据来自 npm `deprecated` 与 crates.io `yanked`，`health` 流程自动采集）。

## 配方 4：内部黑/白名单

```json
{"rules": [
  {"name": "黑名单", "type": "forbidden", "severity": "error",
   "to": "^(left-pad|request)$", "message": "该包已列入公司黑名单"},
  {"name": "仅允许内部 registry 来源", "type": "allowed", "severity": "warn",
   "to": "^(@corp/|lodash$|axios$)"}
]}
```

`allowed` 语义：未命中任何 allowed 规则的声明包违规（白名单收口）。

## 配方 5：强制存在某类依赖（required）

```json
{"rules": [{"name": "必须有测试框架", "type": "required", "severity": "warn",
            "to": "^(jest|vitest|pytest|rspec)$"}]}
```

无任何匹配 → 单条规则级违规（包名记 `*`）。

## 配方 6：边级约束（谁不得依赖谁）

```json
{"rules": [{"name": "工具库不得依赖 web 框架", "type": "forbidden",
            "severity": "warn", "from": "^@corp/tools-", "to": "^(express|flask)"}]}
```

## 与 CI 门禁组合

```bash
# 只对新增违规失败（违规债务管理，见 R12 基线）
python scripts/dependency_analyzer.py analyze-data deps_data.json \
  --rules .dayv/rules.json --ignore-known .dayv-known-violations.json --exit-code 1
```
