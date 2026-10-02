#!/usr/bin/env python3
"""OSV 离线漏洞库 + 查询 TTL 缓存（调研建议 R9，参照 osv-scanner 离线库 +
dependency-cruiser --cache + syft TTL）。

离线库：
- `--download-offline-db` 下载 OSV bulk 导出（osv-vulnerabilities bucket 的
  <ECO>/all.zip）解压到 ~/.dayv/osv_db/<ecosystem>/，附 meta.json 记录下载时间
- `--offline` 只查本地库：受影响判定走 events introduced/fixed 区间比较
  （utils.compare_versions 语义化比较），last_affected/limit/GIT 等复杂区间
  保守跳过并显性计数（未扫描 ≠ 无漏洞，规则 11）

TTL 缓存：
- ~/.dayv/cache/<eco>/<name>-<version>.json 缓存 OSV 查询结果
- 防误报例外（写死）：任一包版本来自范围约束推断（version_inferred）时，
  整批查询 TTL 上限 SAFE_TTL_FOR_INFERRED=300s——缓存过期版本会破坏
  "受影响判定" 前提，绝不允许用 24h 旧缓存配推断版本
"""

import io
import json
import logging
import os
import re
import shutil
import time
import zipfile
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

import ecosystem_registry as eco_reg

logger = logging.getLogger(__name__)

OSV_DOWNLOAD_URL = "https://osv-vulnerabilities.storage.googleapis.com/{eco}/all.zip"

DAYV_HOME = Path(os.path.expanduser("~/.dayv"))
DEFAULT_OSV_DB_DIR = DAYV_HOME / "osv_db"
DEFAULT_CACHE_DIR = DAYV_HOME / "cache"

# 在线默认 TTL（24h）；推断版本的整批查询上限 5 分钟（防误报例外）
DEFAULT_ONLINE_TTL = 24 * 3600
SAFE_TTL_FOR_INFERRED = 300

# 名称大小写归一：pypi/nuget/composer/rubygems/crates 不区分大小写，npm 区分
_CASE_INSENSITIVE_ECOS = {"pypi", "nuget", "composer", "rubygems", "crates"}


# ============ 离线库下载与加载 ============


def _http_get_bytes(url: str) -> bytes:
    from utils import RequestClient

    return RequestClient(timeout=120.0).get(url).content


def download_offline_db(
    ecosystems: List[str],
    dest_dir: Optional[str] = None,
    http_get: Optional[Callable[[str], bytes]] = None,
) -> Dict[str, Dict[str, Any]]:
    """下载各生态 OSV 离线库（覆盖旧目录），返回 {eco: meta}。

    http_get 可注入（测试离线）；下载/解压失败抛异常由调用方显式报告。
    """
    dest = Path(dest_dir or DEFAULT_OSV_DB_DIR)
    getter = http_get or _http_get_bytes
    results: Dict[str, Dict[str, Any]] = {}
    for eco in ecosystems:
        osv_name = eco_reg.osv_ecosystem(eco) or eco
        url = OSV_DOWNLOAD_URL.format(eco=osv_name)
        data = getter(url)
        eco_dir = dest / eco
        if eco_dir.exists():
            shutil.rmtree(eco_dir)
        eco_dir.mkdir(parents=True)
        count = 0
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            for info in z.infolist():
                if info.filename.endswith(".json"):
                    (eco_dir / Path(info.filename).name).write_bytes(z.read(info))
                    count += 1
        meta = {
            "ecosystem": eco,
            "osv_ecosystem": osv_name,
            "downloaded_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "vulns": count,
        }
        (eco_dir / "meta.json").write_text(
            json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        results[eco] = meta
        logger.info(f"离线库已下载 {eco}（{osv_name}）: {count} 条漏洞 → {eco_dir}")
    return results


def db_meta(ecosystem: str, db_dir: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """离线库元信息（含下载时间）；未下载返回 None。"""
    meta_file = Path(db_dir or DEFAULT_OSV_DB_DIR) / ecosystem / "meta.json"
    if not meta_file.is_file():
        return None
    try:
        return json.loads(meta_file.read_text(encoding="utf-8"))
    except Exception:
        return None


def load_offline_db(
    ecosystem: str, db_dir: Optional[str] = None
) -> Optional[Dict[str, dict]]:
    """加载生态离线库 {osv_id: raw_vuln}；未下载返回 None（调用方显式报告）。"""
    eco_dir = Path(db_dir or DEFAULT_OSV_DB_DIR) / ecosystem
    if not eco_dir.is_dir():
        return None
    db: Dict[str, dict] = {}
    for f in sorted(eco_dir.glob("*.json")):
        if f.name == "meta.json":
            continue
        try:
            vuln = json.loads(f.read_text(encoding="utf-8"))
        except Exception:
            logger.debug(f"离线库条目解析失败（跳过）: {f.name}")
            continue
        if isinstance(vuln, dict) and vuln.get("id"):
            db[vuln["id"]] = vuln
    return db


# ============ 离线受影响判定（保守近似 + 复杂区间显性跳过） ============


def _names_equal(registry_name: str, pkg_name: str, ecosystem: str) -> bool:
    if ecosystem in _CASE_INSENSITIVE_ECOS:
        return registry_name.lower() == pkg_name.lower()
    return registry_name == pkg_name


def _range_affects(events: List[Dict[str, Any]], version: str) -> Optional[bool]:
    """单个 range 的 introduced/fixed 链判定。

    Returns:
        True/False=判定结果；None=含 last_affected/limit/无法比较的复杂区间
        （调用方保守跳过并计数，不猜）。
    """
    from utils import compare_versions

    # 事件链按 introduced 分窗
    windows: List[Tuple[str, Optional[str], Optional[str]]] = []
    current_intro: Optional[str] = None
    fixed: Optional[str] = None
    for ev in events or []:
        if not isinstance(ev, dict):
            return None
        if "introduced" in ev:
            if current_intro is not None:
                windows.append((current_intro, fixed, None))
            current_intro = str(ev["introduced"])
            fixed = None
        elif "fixed" in ev:
            fixed = str(ev["fixed"])
        elif "last_affected" in ev or "limit" in ev:
            return None  # 复杂事件：保守跳过
    if current_intro is not None:
        windows.append((current_intro, fixed, None))

    for intro, fix, _ in windows:
        if intro != "0":
            try:
                if compare_versions(version, intro) < 0:
                    continue
            except Exception:
                return None
        if fix is None:
            return True  # 引入后无修复版本：该窗口内全部受影响
        try:
            if compare_versions(version, fix) < 0:
                return True
        except Exception:
            return None
    return False


def _vuln_affects(vuln: dict, pkg) -> bool:
    """OSV vuln 是否影响 pkg（eco+name 匹配 + 任一 range 判定受影响）。"""
    osv_name = eco_reg.osv_ecosystem(pkg.ecosystem)
    if not osv_name:
        return False
    for aff in vuln.get("affected", []) or []:
        if not isinstance(aff, dict):
            continue
        p = aff.get("package") or {}
        if p.get("ecosystem") != osv_name:
            continue
        if not _names_equal(str(p.get("name", "")), pkg.name, pkg.ecosystem):
            continue
        ranges = aff.get("ranges") or []
        if not ranges:
            # 无 ranges 时仅认 exact versions 列表（purl 单列的条目不猜）
            if pkg.version in [str(v) for v in aff.get("versions", []) or []]:
                return True
            continue
        for rng in ranges:
            if not isinstance(rng, dict):
                continue
            if rng.get("type") == "GIT":
                continue  # git SHA 区间与版本无关
            verdict = _range_affects(rng.get("events") or [], pkg.version)
            if verdict is None:
                # 复杂区间无法判定：整体保守返回 None（调用方显性计数，不猜）
                return None
            if verdict:
                return True
    return False


def offline_query(
    packages: List[Any], db_dir: Optional[str] = None
) -> Tuple[List[Dict[str, Any]], Dict[str, List[str]]]:
    """离线批量查询：返回与 dependency_analyzer._classify_osv_packages 的 index
    等长对齐的 results（{"vulns": [...]}），及额外跳过分桶。

    分桶：
    - offline_db_missing: 生态离线库未下载的包（未扫描，显性提示）
    - complex_ranges: 命中复杂受影响区间、保守跳过的包（可能漏报，显性提示）
    """
    results: List[Dict[str, Any]] = []
    skipped: Dict[str, List[str]] = {"offline_db_missing": [], "complex_ranges": []}
    dbs: Dict[str, Optional[Dict[str, dict]]] = {}
    for pkg in packages:
        if pkg.ecosystem not in dbs:
            dbs[pkg.ecosystem] = load_offline_db(pkg.ecosystem, db_dir)
        db = dbs[pkg.ecosystem]
        if db is None:
            skipped["offline_db_missing"].append(
                f"{pkg.name}@{pkg.version} (ecosystem={pkg.ecosystem} 离线库未下载)"
            )
            results.append({})
            continue
        matched = []
        complex_hit = False
        for vuln in db.values():
            try:
                hit = _vuln_affects(vuln, pkg)
            except Exception:
                hit = None
            if hit is None:
                complex_hit = True
            elif hit:
                matched.append(vuln)
        if complex_hit:
            skipped["complex_ranges"].append(
                f"{pkg.name}@{pkg.version} (存在 last_affected/limit 等复杂区间，保守跳过)"
            )
        results.append({"vulns": matched})
    return results, skipped


# ============ TTL 缓存 ============


def effective_ttl(base_ttl: Optional[int], any_inferred: bool) -> Optional[int]:
    """整批查询的生效 TTL。

    防误报例外（写死）：任一包版本为推断下界时，TTL 收敛到
    SAFE_TTL_FOR_INFERRED（≤5 分钟）——过期版本号配旧缓存会漏报新漏洞。
    base_ttl=None 表示禁用缓存。
    """
    if base_ttl is None:
        return None
    if any_inferred:
        return min(base_ttl, SAFE_TTL_FOR_INFERRED)
    return base_ttl


def cache_path(
    ecosystem: str, name: str, version: str, cache_dir: Optional[str] = None
) -> Path:
    safe = re.sub(r"[^A-Za-z0-9._@/:-]", "_", f"{name}-{version}")
    return Path(cache_dir or DEFAULT_CACHE_DIR) / ecosystem / f"{safe}.json"


def cache_read(
    ecosystem: str,
    name: str,
    version: str,
    max_age_s: int,
    cache_dir: Optional[str] = None,
    now: Optional[float] = None,
) -> Optional[List[dict]]:
    """读缓存；超期/损坏/不存在返回 None。"""
    p = cache_path(ecosystem, name, version, cache_dir)
    if not p.is_file():
        return None
    try:
        ts = now if now is not None else time.time()
        if ts - p.stat().st_mtime > max_age_s:
            return None
        data = json.loads(p.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else None
    except Exception:
        logger.debug(f"缓存读取失败（按未命中处理）: {p}")
        return None


def cache_write(
    ecosystem: str,
    name: str,
    version: str,
    vulns: List[dict],
    cache_dir: Optional[str] = None,
) -> None:
    """写缓存；失败仅 debug（缓存是优化不是数据源，写失败不影响正确性）。"""
    p = cache_path(ecosystem, name, version, cache_dir)
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(vulns, ensure_ascii=False), encoding="utf-8")
    except Exception:
        logger.debug(f"缓存写入失败: {p}", exc_info=True)
