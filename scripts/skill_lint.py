#!/usr/bin/env python3
"""skill-lint — 自研 skill 仓库工程基线体检（自包含单文件，可 vendored 进各仓 CI）

用法:
    python3 scripts/skill_lint.py                # 体检工作区全部自研 skill 仓
    python3 scripts/skill_lint.py <repo> [...]   # 体检指定仓（CI 用法：python3 scripts/skill_lint.py .）

检查项（FAIL 阻断 / WARN 提示）:
  FAIL  SKILL.md 存在；frontmatter 闭合且含 name/description；name 与目录名一致；
        description ≤1024 字符；.gitignore 含 specmark/（全局规则 24）；
        JSON 资产（skill.json/test-prompts.json/evals/*.json/根级 *.json）可解析；
        frontmatter metadata 与 skill.json version 一致；
        SKILL.md 与 references/**/*.md 中引用的 .md 路径存在；
        可选 lint-checks.json 声明的仓内自检规则未满足（require-pattern /
        file-header / cli-subcommands 三类，按仓 opt-in；配置本身非法同样
        FAIL）。cli-subcommands：运行 cli 的 --help 取实际子命令集合，断言
        每个实际子命令以反引号形式出现在 doc 中，且 doc 的子命令表（行首
        | `cmd` | 形态）不列出不存在的命令——文档与 CLI 行为一致性门禁。
  WARN  frontmatter metadata 缺失（agentskills 规范）；SKILL.md >500 行；
        scripts/ 有可执行脚本但无 tests/；references 孤儿文件；LICENSE 缺失。

退出码: 0=无 FAIL（WARN 不阻断）; 1=存在 FAIL。

lint-checks.json（仓根，可选）schema:
  {"checks": [
    {"name": "规则名", "type": "require-pattern",          # type 缺省为 require-pattern
     "file": "references/guide.md", "pattern": "<regex>",
     "min_count": 1,                                       # 缺省 1
     "severity": "FAIL"},                                  # 缺省 FAIL，可 WARN
    {"name": "资产文件头三要素", "type": "file-header",
     "dirs": ["references/commands", "references/templates"],
     "fields": ["来源", "许可", "核验日期"]}                # fields 缺省即三要素
  ]}
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

MAX_DESC = 1024
MAX_SKILLMD_LINES = 500
SKIP_DIR_NAMES = {
    ".git",
    ".github",
    ".claude",
    ".claude-plugin",
    ".analysis",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "__pycache__",
    "node_modules",
    "specmark",
    "openspec",
    "corpus",
    "temp",
    ".attic",
    "logs",
    "open-code-review",
}
MD_LINK_RE = re.compile(r"\]\(([\w][\w./-]*\.md)(?:#[^)]*)?\)")
INTERNAL_PATH_RE = re.compile(
    r"`?(?<![-\w/])((?:references|scripts|tests)/[\w./-]*\.md)\b`?"
)
ANY_PATH_RE = re.compile(r"`?(?<![\w./-])([\w][\w./-]*/[\w./-]*\.md)\b`?")
CODE_FENCE_RE = re.compile(r"```.*?```", re.DOTALL)
FRONTMATTER_RE = re.compile(r"\A---\r?\n(.*?)\r?\n---\r?\n", re.DOTALL)


def strip_code(text: str) -> str:
    return CODE_FENCE_RE.sub("", text)


def check_links(repo: Path) -> tuple[list[str], list[str]]:
    """返回 (fail 列表, warn 列表)。

    FAIL 只针对仓库内资产：markdown 链接目标、references//scripts//tests/ 开头的路径。
    其余带斜杠的 .md（如上游项目文件、示例产物路径）降为 WARN。
    裸文件名（design.md、ATTACK-CLASSES.md）属散文提及，不做判定。
    """
    fails: list[str] = []
    warns: list[str] = []
    seen: set[tuple[str, str]] = set()

    def resolve(src: Path, raw: str) -> bool:
        # markdown 渲染器按源文件相对解析链接：src 在仓根时等价于仓根相对
        return (src.parent / raw).is_file()

    def escapes(raw: str) -> bool:
        """跨仓/外部仓引用（../ 开头，或解析后落在仓外）——仓内无法校验。"""
        if raw.startswith("../"):
            return True
        try:
            (src_dir / raw).resolve().relative_to(repo.resolve())
            return False
        except ValueError:
            return True

    sources = (
        [repo / "SKILL.md"]
        + repo_files(repo, "references", (".md",))
        + [repo / "README.md", repo / "README_EN.md"]
    )
    for src in sources:
        if not src.is_file():
            continue
        text = strip_code(src.read_text(encoding="utf-8", errors="replace"))
        src_dir = src.parent
        internal = {m for m in INTERNAL_PATH_RE.findall(text)} | {
            m for m in MD_LINK_RE.findall(text)
        }
        other = set(ANY_PATH_RE.findall(text)) - internal
        for raw in sorted(internal):
            key = (str(src.relative_to(repo)), raw)
            if key in seen or resolve(src, raw):
                continue
            seen.add(key)
            (warns if escapes(raw) else fails).append(f"{key[0]} -> {raw}")
        for raw in sorted(other):
            key = (str(src.relative_to(repo)), raw)
            if key in seen or resolve(src, raw):
                continue
            seen.add(key)
            warns.append(f"{key[0]} -> {raw}")
    return fails, warns


def check_orphans(repo: Path) -> list[str]:
    refs = repo_files(repo, "references", (".md",))
    if not refs:
        return []
    tokens: set[str] = set()
    for p in [repo / "SKILL.md"] + refs:
        if p.is_file():
            for tok in re.findall(
                r"[\w./-]+", strip_code(p.read_text(encoding="utf-8", errors="replace"))
            ):
                # 路径 token 的各级后缀均视为引用形态：references/x.md、../references/x.md、x.md 同指一文件
                segs = tok.split("/")
                for i in range(len(segs)):
                    tokens.add("/".join(segs[i:]))
    orphans = []
    for p in refs:
        if p.name == "index.md":
            continue
        stem_rel = str(p.relative_to(repo / "references"))
        if p.stem in tokens or stem_rel in tokens or p.name in tokens:
            continue
        orphans.append(stem_rel)
    return orphans


def check_repo_rules(repo: Path) -> tuple[list[str], list[str]]:
    """可选 lint-checks.json 声明的仓内自检规则（按仓 opt-in，无此文件即跳过）。

    规则错误（目标文件缺失/非法正则/未知键/未知 type/severity 非法）一律 FAIL，
    不随规则自身的 severity 降级——配置写错必须显性化，不能静默跳过。
    """
    fails: list[str] = []
    warns: list[str] = []
    name = repo.name
    cfg_path = repo / "lint-checks.json"
    if not cfg_path.is_file():
        return fails, warns
    try:
        cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return [f"{name}: lint-checks.json 非法 JSON: {exc}"], warns
    if (
        not isinstance(cfg, dict)
        or set(cfg) != {"checks"}
        or not isinstance(cfg["checks"], list)
    ):
        return [f'{name}: lint-checks.json 顶层必须是 {{"checks": [...]}} 映射'], warns
    for i, rule in enumerate(cfg["checks"], 1):
        where = f"lint-checks.json checks[{i}]"
        if not isinstance(rule, dict):
            fails.append(f"{name}: {where} 不是对象")
            continue
        unknown = set(rule) - {
            "name",
            "type",
            "file",
            "pattern",
            "min_count",
            "dirs",
            "fields",
            "severity",
            "cli",
            "doc",
        }
        if unknown:
            fails.append(f"{name}: {where} 未知键: {sorted(unknown)}")
            continue
        rtype = rule.get("type", "require-pattern")
        if rtype not in ("require-pattern", "file-header", "cli-subcommands"):
            fails.append(f"{name}: {where} 未知 type: {rtype!r}")
            continue
        sev = rule.get("severity", "FAIL")
        if sev not in ("FAIL", "WARN"):
            fails.append(f"{name}: {where} severity 只能是 FAIL/WARN")
            continue
        rname = str(rule.get("name") or where)
        if rtype == "require-pattern":
            rel, pattern = rule.get("file"), rule.get("pattern")
            if not rel or not pattern:
                fails.append(f"{name}: {where} require-pattern 需要 file 与 pattern")
                continue
            target = repo / rel
            if not target.is_file():
                fails.append(f"{name}: {where} 目标文件不存在: {rel}")
                continue
            min_count = rule.get("min_count", 1)
            if not isinstance(min_count, int) or min_count < 1:
                fails.append(f"{name}: {where} min_count 必须为 ≥1 整数")
                continue
            try:
                found = len(
                    re.findall(
                        pattern, target.read_text(encoding="utf-8", errors="replace")
                    )
                )
            except re.error as exc:
                fails.append(f"{name}: {where} 非法正则: {exc}")
                continue
            if found < min_count:
                bucket = fails if sev == "FAIL" else warns
                bucket.append(
                    f"{name}: {rname} 未满足（{rel} 命中 {found}/{min_count}）"
                )
        elif rtype == "cli-subcommands":
            cli_rel, doc_rel = rule.get("cli"), rule.get("doc")
            if not cli_rel or not doc_rel:
                fails.append(f"{name}: {where} cli-subcommands 需要 cli 与 doc")
                continue
            cli_path, doc_path = repo / cli_rel, repo / doc_rel
            if not cli_path.is_file() or not doc_path.is_file():
                fails.append(
                    f"{name}: {where} cli/doc 文件不存在: {cli_rel} / {doc_rel}"
                )
                continue
            import subprocess

            try:
                proc = subprocess.run(
                    [sys.executable, str(cli_path), "--help"],
                    capture_output=True,
                    text=True,
                    timeout=60,
                    check=False,
                )
            except Exception as exc:
                fails.append(f"{name}: {where} 无法运行 {cli_rel} --help: {exc}")
                continue
            m = re.search(r"\{([^{}]+)\}", proc.stdout)
            if not m or not proc.stdout.strip():
                fails.append(
                    f"{name}: {where} {cli_rel} --help 无有效输出"
                    f"（依赖未安装或非子命令式 CLI？）"
                )
                continue
            actual = {c.strip() for c in m.group(1).split(",") if c.strip()}
            doc_text = doc_path.read_text(encoding="utf-8", errors="replace")
            missing = sorted(
                cmd
                for cmd in actual
                if f"`{cmd}`" not in doc_text
                and f"`{cmd} " not in doc_text
                and f"`{cmd}|`" not in doc_text
            )
            table_cmds: list[str] = []
            for line in doc_text.splitlines():
                lm = re.match(r"^\s*\|\s*`([\w-]+)`", line)
                if lm:
                    table_cmds.append(lm.group(1))
            extra = sorted(set(table_cmds) - actual)
            if missing:
                bucket = fails if sev == "FAIL" else warns
                bucket.append(
                    f"{name}: {rname} 实际子命令未在 {doc_rel} 以反引号提及: {missing}"
                )
            if extra:
                bucket = fails if sev == "FAIL" else warns
                bucket.append(
                    f"{name}: {rname} {doc_rel} 子命令表列出不存在的命令: {extra}"
                )
        else:  # file-header
            dirs, fields = (
                rule.get("dirs"),
                rule.get("fields", ["来源", "许可", "核验日期"]),
            )
            if not dirs or not fields:
                fails.append(f"{name}: {where} file-header 需要 dirs 与 fields")
                continue
            assets: list[Path] = []
            for d in dirs:
                base = repo / d
                if base.is_dir():
                    assets.extend(sorted(base.rglob("*.md")))
            if not assets:
                warns.append(f"{name}: {rname} 未找到资产文件（dirs={dirs} 为空）")
                continue
            for p in assets:
                text = p.read_text(encoding="utf-8", errors="replace")
                missing = [f for f in fields if f not in text]
                if missing:
                    bucket = fails if sev == "FAIL" else warns
                    bucket.append(
                        f"{name}: {rname} 缺少 {'、'.join(missing)}: {p.relative_to(repo)}"
                    )
    return fails, warns


def parse_frontmatter(text: str):
    """返回 (dict, error)。优先用 PyYAML，缺失时退回逐行解析。"""
    m = FRONTMATTER_RE.match(text)
    if not m:
        return None, "缺少或未闭合的 YAML frontmatter"
    block = m.group(1)
    try:
        import yaml  # type: ignore

        data = yaml.safe_load(block)
        if not isinstance(data, dict):
            return None, "frontmatter 不是键值映射"
        return data, None
    except ImportError:
        data: dict[str, object] = {}
        key = None
        for line in block.splitlines():
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            m2 = re.match(r"^([A-Za-z0-9_-]+):\s*(.*)$", line)
            if m2:
                key = m2.group(1)
                data[key] = m2.group(2).strip().strip("\"'")
            elif key and re.match(r"^\s+\S", line):
                m3 = re.match(r"^\s+([A-Za-z0-9_-]+):\s*(.*)$", line)
                if m3:
                    # 一层嵌套子键（如 metadata.version）必须成 dict，否则 string→string 校验在无 PyYAML 环境误报 FAIL
                    if not isinstance(data.get(key), dict):
                        data[key] = {}
                    data[key][m3.group(1)] = m3.group(2).strip().strip("\"'")
                else:
                    data[key] = (
                        f"{data[key]} {line.strip()}" if data.get(key) else line.strip()
                    )
        return data, None
    except Exception as exc:  # yaml 解析错误
        return None, f"frontmatter YAML 非法: {exc}"


def repo_files(repo: Path, sub: str, suffixes: tuple[str, ...]) -> list[Path]:
    base = repo / sub
    if not base.is_dir():
        return []
    out = []
    for root, dirs, files in os.walk(base):
        dirs[:] = [d for d in dirs if d not in SKIP_DIR_NAMES]
        for fn in files:
            p = Path(root) / fn
            if p.suffix in suffixes:
                out.append(p)
    return sorted(out)


def lint_repo(repo: Path) -> tuple[list[str], list[str]]:
    fails: list[str] = []
    warns: list[str] = []
    name = repo.name

    skill_md = repo / "SKILL.md"
    if not skill_md.is_file():
        return [f"{name}: 缺少 SKILL.md"], []
    text = skill_md.read_text(encoding="utf-8", errors="replace")

    fm, err = parse_frontmatter(text)
    if err:
        fails.append(f"{name}: {err}")
        fm = {}
    else:
        if fm.get("name") != name:
            fails.append(
                f"{name}: frontmatter name={fm.get('name')!r} 与目录名不一致（agentskills 规范要求同名）"
            )
        desc = str(fm.get("description", ""))
        if not desc:
            fails.append(f"{name}: frontmatter 缺 description")
        elif len(desc) > MAX_DESC:
            fails.append(f"{name}: description {len(desc)} 字符，超过 {MAX_DESC} 上限")

    skill_json = repo / "skill.json"
    if skill_json.is_file():
        try:
            sj = json.loads(skill_json.read_text(encoding="utf-8"))
        except Exception as exc:
            fails.append(f"{name}: skill.json 非法 JSON: {exc}")
            sj = None
        if isinstance(sj, dict) and fm:
            meta = fm.get("metadata")
            if meta is None:
                warns.append(
                    f"{name}: frontmatter 缺 metadata（agentskills 规范；version/author/repo 应与 skill.json 对齐）"
                )
            elif isinstance(meta, dict):
                if meta.get("version") != sj.get("version"):
                    fails.append(
                        f"{name}: metadata.version={meta.get('version')!r} 与 skill.json version={sj.get('version')!r} 不一致"
                    )
            else:
                fails.append(f"{name}: frontmatter metadata 必须是 string→string 映射")

    gi = repo / ".gitignore"
    if not gi.is_file() or not re.search(
        r"^specmark/?$", gi.read_text(encoding="utf-8", errors="replace"), re.MULTILINE
    ):
        fails.append(f"{name}: .gitignore 缺 specmark/ 规则（全局规则 24）")

    json_assets = repo_files(repo, ".", (".json",))
    for p in json_assets:
        try:
            json.loads(p.read_text(encoding="utf-8"))
        except Exception as exc:
            fails.append(f"{name}: {p.relative_to(repo)} 非法 JSON: {exc}")

    lines = text.count("\n") + 1
    if lines > MAX_SKILLMD_LINES:
        warns.append(
            f"{name}: SKILL.md {lines} 行，超过 {MAX_SKILLMD_LINES} 行建议上限"
        )

    link_fails, link_warns = check_links(repo)
    for miss in link_fails:
        fails.append(f"{name}: 引用不存在的仓库内文档 {miss}")
    if link_warns:
        sample = "；".join(link_warns[:3])
        warns.append(
            f"{name}: {len(link_warns)} 处外部/示例路径未在本仓命中（多为上游项目或示例产物，确认非笔误即可）{sample}"
        )

    scripts = [
        p
        for p in repo_files(repo, "scripts", (".py", ".sh"))
        if p.name != "skill_lint.py"
    ]
    tests = [
        p for p in repo_files(repo, "tests", (".py",)) if p.name.startswith("test")
    ]
    if scripts and not tests:
        warns.append(
            f"{name}: scripts/ 有 {len(scripts)} 个脚本但无 tests/ 覆盖（K-Dense 覆盖守卫口径）"
        )

    orphans = check_orphans(repo)
    if orphans:
        warns.append(
            f"{name}: {len(orphans)} 个 references 文件未被任何文档引用（导航挂载待审计，勿贸然删除）："
            + "；".join(orphans[:3])
        )

    rule_fails, rule_warns = check_repo_rules(repo)
    fails.extend(rule_fails)
    warns.extend(rule_warns)

    vendored = repo / "scripts" / "skill_lint.py"
    canonical = Path(__file__).resolve()
    if (
        vendored.is_file()
        and vendored.resolve() != canonical
        and vendored.read_bytes() != canonical.read_bytes()
    ):
        fails.append(
            f"{name}: scripts/skill_lint.py vendored 副本与工作区正本不一致（重跑 scripts/vendor-skill-lint.sh 分发）"
        )

    if not (repo / "LICENSE").is_file():
        warns.append(f"{name}: 缺 LICENSE 文件")

    return fails, warns


def discover(workspace: Path) -> list[Path]:
    repos = []
    for child in sorted(workspace.iterdir()):
        if not child.is_dir() or child.name.startswith("."):
            continue
        if (child / "SKILL.md").is_file() and (child / ".git").exists():
            repos.append(child)
    return repos


def main(argv: list[str]) -> int:
    if len(argv) > 1:
        repos = [Path(a).resolve() for a in argv[1:]]
    else:
        repos = discover(Path(__file__).resolve().parent.parent)
    if not repos:
        print("未发现任何 skill 仓库（需含 SKILL.md 与 .git/）")
        return 1

    total_fail = total_warn = 0
    for repo in repos:
        fails, warns = lint_repo(repo)
        total_fail += len(fails)
        total_warn += len(warns)
        status = "FAIL" if fails else ("WARN" if warns else "PASS")
        print(f"[{status:4}] {repo.name}  ({len(fails)} fail / {len(warns)} warn)")
        for f in fails:
            print(f"         ✗ {f.split(': ', 1)[-1]}")
        for w in warns:
            print(f"         · {w.split(': ', 1)[-1]}")
    print(f"\n合计：{len(repos)} 仓，{total_fail} FAIL，{total_warn} WARN")
    return 1 if total_fail else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
