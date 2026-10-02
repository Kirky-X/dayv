#!/usr/bin/env python3
"""
Monitor - 漏洞持续监控
定时扫描项目依赖的漏洞状态，检测新漏洞时告警

设计契约:
- run_scan(project_path, scanner=None) -> dict:
    执行一次扫描，返回 {timestamp, project_path, vulnerabilities, total}
- compare_with_history(current, history_file) -> list:
    找出新增漏洞（current 有，history 最近一次没有的）
- save_scan_to_history(current, history_file) -> None:
    保存扫描结果到历史文件（限制 MAX_HISTORY_ENTRIES 条）
- send_alert(webhook_url, new_vulns, http_client=None) -> bool:
    POST JSON 到 webhook，成功 True / 失败 False（不抛异常）
- generate_cron_entry(schedule, project_path) -> str:
    生成 crontab 条目字符串（不实际安装）
- format_alert(new_vulns) -> str:
    格式化告警文本

历史文件: ~/.dayv/monitor_history.json
历史格式: [{timestamp, project_path, vulnerabilities, total}, ...]
"""

import json
import logging
import os
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)


# ============ 常量 ============

DEFAULT_HISTORY_FILE = os.path.expanduser("~/.dayv/monitor_history.json")
MAX_HISTORY_ENTRIES = 50


# ============ 主函数 ============


def run_scan(project_path: str,
             scanner: Optional[Callable[..., List[Dict[str, Any]]]] = None,
             offline: bool = False,
             cache: bool = False) -> Dict[str, Any]:
    """
    执行一次漏洞扫描

    Args:
        project_path: 项目路径
        scanner: 可注入的扫描函数 (project_path, offline=…, cache=…) -> list
                 默认走 DependencyAnalyzer.assess_security
        offline: True 时扫描只查本地 OSV 离线库（R9，需先下载离线库）
        cache: True 时启用 OSV 查询 TTL 缓存（R9，~/.dayv/cache）

    Returns:
        {timestamp, project_path, vulnerabilities, total}
    """
    if scanner is None:
        scanner = _default_scanner

    vulnerabilities = scanner(project_path, offline=offline, cache=cache)

    return {
        "timestamp": float(time.time()),
        "project_path": str(project_path),
        "vulnerabilities": vulnerabilities,
        "total": len(vulnerabilities),
    }


def compare_with_history(current: Dict[str, Any],
                         history_file: str) -> List[Dict[str, Any]]:
    """
    对比当前扫描结果与历史记录，找出新增漏洞

    Args:
        current: run_scan 的返回值
        history_file: 历史文件路径

    Returns:
        新增漏洞列表（current 有，history 最近一次没有的）
        无历史文件时，所有漏洞都视为新增
    """
    history = _load_history(history_file)
    if not history:
        # 无历史，所有漏洞都视为新增
        return list(current.get("vulnerabilities", []))

    # 取最近一次扫描
    latest = history[-1]
    old_keys = set()
    for v in latest.get("vulnerabilities", []):
        cve = v.get("cve_id", "")
        pkg = v.get("package", "")
        old_keys.add((cve, pkg))

    new_vulns: List[Dict[str, Any]] = []
    for v in current.get("vulnerabilities", []):
        cve = v.get("cve_id", "")
        pkg = v.get("package", "")
        if (cve, pkg) not in old_keys:
            new_vulns.append(v)

    return new_vulns


def save_scan_to_history(current: Dict[str, Any], history_file: str) -> None:
    """
    保存扫描结果到历史文件

    Args:
        current: run_scan 的返回值
        history_file: 历史文件路径（父目录不存在时自动创建）
    """
    history = _load_history(history_file)
    history.append({
        "timestamp": current.get("timestamp", time.time()),
        "project_path": current.get("project_path", ""),
        "vulnerabilities": current.get("vulnerabilities", []),
        "total": current.get("total", 0),
    })

    # 限制最大条数，保留最新的
    if len(history) > MAX_HISTORY_ENTRIES:
        history = history[-MAX_HISTORY_ENTRIES:]

    _write_history(history, history_file)


def send_alert(webhook_url: str,
               new_vulns: List[Dict[str, Any]],
               http_client: Optional[Any] = None) -> bool:
    """
    POST JSON 告警到 webhook

    Args:
        webhook_url: webhook URL
        new_vulns: 新漏洞列表
        http_client: 可注入的 HTTP 客户端（需有 .post(url, json=...) 方法）
                     默认用 httpx.Client

    Returns:
        True=发送成功, False=发送失败（不抛异常，显性化返回）
    """
    if not new_vulns:
        logger.info("无新漏洞，跳过 webhook 告警")
        return True

    payload = {
        "alert_type": "dayv_new_vulnerabilities",
        "count": len(new_vulns),
        "vulnerabilities": new_vulns,
        "message": format_alert(new_vulns),
    }

    try:
        if http_client is None:
            import httpx
            with httpx.Client(timeout=30.0) as client:
                resp = client.post(webhook_url, json=payload)
                resp.raise_for_status()
                return True
        else:
            resp = http_client.post(webhook_url, json=payload)
            resp.raise_for_status()
            return True
    except Exception as e:
        logger.error(f"webhook 告警失败: {e}")
        return False


def generate_cron_entry(schedule: str, project_path: str) -> str:
    """
    生成 crontab 条目字符串（不实际安装到 crontab）

    Args:
        schedule: cron schedule 表达式（如 "0 9 * * *"）
        project_path: 项目路径

    Returns:
        crontab 条目字符串
    """
    script_path = Path(__file__).parent / "dependency_analyzer.py"
    log_file = f"/tmp/dayv-monitor-{Path(project_path).name}.log"
    return (
        f"{schedule} cd {project_path} && "
        f"/usr/bin/env python3 {script_path} monitor {project_path} "
        f">> {log_file} 2>&1"
    )


def format_alert(new_vulns: List[Dict[str, Any]]) -> str:
    """
    格式化告警文本

    Args:
        new_vulns: 新漏洞列表

    Returns:
        告警文本，格式:
        [DAYV ALERT] 检测到 N 个新漏洞
        - CVE-XXXX (severity) on pkg@version
    """
    if not new_vulns:
        return "[DAYV ALERT] 无新漏洞"

    count = len(new_vulns)
    lines = [f"[DAYV ALERT] 检测到 {count} 个新漏洞"]
    for v in new_vulns:
        cve = v.get("cve_id", "UNKNOWN")
        pkg = v.get("package", "unknown")
        ver = v.get("version", "")
        severity = v.get("severity", "unknown")
        lines.append(f"- {cve} ({severity}) on {pkg}@{ver}")

    return "\n".join(lines)


# ============ 私有工具函数 ============


def _default_scanner(project_path: str, offline: bool = False, cache: bool = False) -> List[Dict[str, Any]]:
    """
    默认 scanner: 用 DependencyAnalyzer 跑漏洞扫描

    Args:
        project_path: 项目路径
        offline: True 时只查本地 OSV 离线库（R9）
        cache: True 时启用 OSV 查询 TTL 缓存（R9）

    Returns:
        漏洞列表（dict schema，与 report_to_dict 输出一致）
    """
    # 延迟 import 避免 circular import
    import dependency_analyzer

    packages, edges, _ = dependency_analyzer.parse_dependencies(project_path)
    cache_ttl = None
    if cache:
        import osv_offline

        cache_ttl = osv_offline.DEFAULT_ONLINE_TTL
    analyzer = dependency_analyzer.DependencyAnalyzer(
        offline_db=offline, cache_ttl=cache_ttl
    )

    # 豁免清单（R7）：项目目录的 .dayv.toml 自动探测；配置非法显式失败不静默
    import exemptions as exemptions_mod

    auto_config = exemptions_mod.find_config_file(project_path)
    if auto_config:
        logger.info(f"自动加载豁免配置: {auto_config}")
        analyzer.exemptions = exemptions_mod.load_exemptions(str(auto_config))

    try:
        analyzer.build_dependency_graph(packages, edges)
        vulns = analyzer.assess_security()
        return [
            {
                "cve_id": v.cve_id,
                "package": v.package,
                "version": v.version,
                "severity": v.severity.value,
                "description": v.description,
                "fixed_version": v.fixed_version,
            }
            for v in vulns
        ]
    finally:
        analyzer.close()


def _load_history(history_file: str) -> List[Dict[str, Any]]:
    """加载历史记录，文件不存在或解析失败时返回空列表"""
    path = Path(history_file)
    if not path.exists():
        return []

    try:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            return data
        logger.warning(f"历史文件格式错误（非 list）: {history_file}")
        return []
    except (json.JSONDecodeError, OSError) as e:
        logger.warning(f"读取历史文件失败: {e}")
        return []


def _write_history(history: List[Dict[str, Any]], history_file: str) -> None:
    """写入历史记录（自动创建父目录）"""
    path = Path(history_file)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        json.dump(history, f, indent=2, ensure_ascii=False)
