#!/usr/bin/env python3
"""
Dependency Analysis Engine - 依赖分析引擎
基于 Ladybug 图数据库实现依赖关系分析、冲突检测、版本推荐等功能

使用方式:
  # 分析项目依赖
  python dependency_analyzer.py analyze /path/to/project

  # 查询包依赖
  python dependency_analyzer.py query <package-name>

  # 搜索包
  python dependency_analyzer.py search <keyword>

  # 检查安全漏洞
  python dependency_analyzer.py security <package-name>

  # 生成完整报告
  python dependency_analyzer.py report /path/to/project -o report.json
"""

import argparse
import json
import logging
import re
import sys
import tempfile
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    import real_ladybug as lb
except ImportError:
    import sys as _sys

    _sys.stderr.write(
        "错误：缺少依赖 real_ladybug（图数据库，必需）。\n"
        "请在 skill 根目录执行: pip install -r requirements.txt\n"
        "或单独安装: pip install real-ladybug\n"
    )
    _sys.exit(1)

import ecosystem_registry as eco_reg
import purl as purl_mod
from utils import (
    RequestClient,
    check_version_constraint,
    compare_versions,
    find_latest_version,
    is_valid_semver,
    sort_versions,
)
from vulnerability_prioritizer import parse_cvss_v3_base_score

# 配置日志
logger = logging.getLogger(__name__)

# 常量定义
MAX_CYCLES_DETECT = 100
MAX_PATHS_FIND = 10
MAX_RECOMMENDATIONS_DISPLAY = 20

# ============ OSV 漏洞数据库集成 ============
# OSV batch query API（官方文档：https://google.github.io/osv.dev/post-v1-querybatch/）
# 注：任务原文写 "/v1/query"，但 OSV 的真正 batch 端点是 "/v1/querybatch"
# （单包端点 /v1/query 不支持批量提交）。按"batch 提交"意图采用 /v1/querybatch。
OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_BATCH_CHUNK = 250  # OSV querybatch 上限 1000，保守分片

# 退出码契约（R3，参照 osv-scanner 0/1/127/128 语义）：
#   0   = 成功（含"未发现漏洞"）
#   N   = --exit-code N 且发现漏洞（默认 0 保持兼容，不破坏既有调用方）
#   128 = 输入/解析失败（manifest/lockfile/deps_data 缺失或格式非法）
EXIT_INPUT_ERROR = 128

# 内部 ecosystem 标识 → OSV ecosystem 名（单一来源：ecosystem_registry）
OSV_ECOSYSTEM_MAP = {
    eco: meta["osv_ecosystem"] for eco, meta in eco_reg.ECOSYSTEMS.items()
}


def _severity_from_cvss(score: float) -> "SeverityLevel":
    """按 CVSS v3 标准分档把数值分映射到 SeverityLevel（确定性判断）。"""
    if score >= 9.0:
        return SeverityLevel.CRITICAL
    if score >= 7.0:
        return SeverityLevel.HIGH
    if score >= 4.0:
        return SeverityLevel.MEDIUM
    return SeverityLevel.LOW


class SeverityLevel(Enum):
    """严重级别"""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class DependencyNode:
    """依赖节点"""

    name: str
    version: str
    ecosystem: str  # pypi, npm, maven, crates
    is_root: bool = False
    # version 是从范围约束（^1.2.0 / ~1.2.3 / >=2.0 等）推断的下界而非精确锁定。
    # 无法得到确定版本的包 version 为空串（禁止编造 "0.0.0" 送 OSV 查询）。
    version_inferred: bool = False
    # version 来自 lockfile 精确锁定（package-lock.json/poetry.lock/Cargo.lock 等），
    # OSV 受影响判定不再保守近似（与 version_inferred 互斥）
    version_resolved: bool = False
    properties: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DependencyEdge:
    """依赖边"""

    source: str
    target: str
    constraint: str
    edge_type: str = "depends_on"  # depends_on, conflicts_with, optional
    properties: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ConflictInfo:
    """冲突信息"""

    package: str
    required_by: List[Dict[str, str]]
    conflict_type: str
    severity: SeverityLevel
    suggestion: str


@dataclass
class SecurityVulnerability:
    """安全漏洞"""

    package: str
    version: str
    severity: SeverityLevel
    cve_id: str
    description: str
    fixed_version: Optional[str] = None
    references: List[str] = field(default_factory=list)
    # OSV 真实 CVSS 数据（来自 severity[].score，供 prioritizer 精确评分）
    cvss_vector: Optional[str] = None
    cvss_score: Optional[float] = None
    # OSV aliases（GHSA↔CVE 等连带标识；豁免清单按 id+alias 命中）
    aliases: List[str] = field(default_factory=list)


@dataclass
class UpdatePath:
    """更新路径"""

    package: str
    current_version: str
    target_version: str
    steps: List[str]
    breaking_changes: List[str]
    recommendation: str


@dataclass
class AnalysisReport:
    """分析报告"""

    timestamp: float
    root_package: str
    total_packages: int
    total_edges: int
    conflicts: List[ConflictInfo]
    vulnerabilities: List[SecurityVulnerability]
    update_paths: List[UpdatePath]
    recommendations: List[str]
    graph_stats: Dict[str, Any]
    # 漏洞扫描状态告警（如 OSV 请求失败时显式标注"未扫描"，避免静默谎报"无漏洞"）
    scan_warnings: List[str] = field(default_factory=list)
    # 依赖许可证合规数据：非根包的 license 列表；无法获取的显式标 "UNKNOWN"
    license_info: List[Dict[str, str]] = field(default_factory=list)
    # 被豁免清单过滤掉的漏洞（逐条带 reason/过期日，不静默消失——规则 11）
    ignored_vulnerabilities: List[Dict[str, str]] = field(default_factory=list)


# ============ OSV 响应解析（纯函数，便于离线单测） ============


def _classify_osv_packages(
    packages: List[DependencyNode],
) -> Tuple[List[DependencyNode], List[str], List[str]]:
    """按 OSV 可查性把包分成三类（跳过原因分桶的唯一判定点）。

    Returns:
        (index, unmapped_ecosystem, no_version)
        - index: 可提交查询的包（生态已映射且有确定版本）
        - unmapped_ecosystem: 生态系统未映射 OSV 的包描述
        - no_version: 无确定版本的包描述
    """
    index: List[DependencyNode] = []
    unmapped: List[str] = []
    no_version: List[str] = []
    for pkg in packages:
        if pkg.ecosystem not in OSV_ECOSYSTEM_MAP:
            unmapped.append(f"{pkg.name}@{pkg.version} (ecosystem={pkg.ecosystem})")
        elif not pkg.version:
            no_version.append(f"{pkg.name} (无版本，OSV 无法判定受影响范围)")
        else:
            index.append(pkg)
    return index, unmapped, no_version


def _osv_query_for(pkg: DependencyNode) -> Dict[str, Any]:
    """构造单个包的 OSV querybatch 查询项。

    package.purl 由 purl 单点模块构造（osv-scanner 同款标识，提升
    maven/nuget 等歧义名匹配）；构造失败时仅省略 purl 字段，不影响
    ecosystem+name+version 的既有匹配路径。
    """
    package: Dict[str, Any] = {
        "ecosystem": OSV_ECOSYSTEM_MAP[pkg.ecosystem],
        "name": pkg.name,
    }
    purl_str = purl_mod.make_purl(pkg.name, pkg.ecosystem, pkg.version or None)
    if purl_str:
        package["purl"] = purl_str
    return {
        "package": package,
        "version": pkg.version,
    }


def _build_osv_queries(
    packages: List[DependencyNode],
) -> Tuple[List[Dict[str, Any]], List[DependencyNode], List[str]]:
    """把 DependencyNode 列表转成 OSV querybatch 的 queries 数组。

    Returns:
        (queries, index, skipped)
        - queries: 与 index 等长对齐的 OSV query 列表
        - index: 实际提交查询的包（与 queries[k] 一一对应）
        - skipped: 被跳过的包描述（生态系统未映射 / 无版本，扁平列表）
    """
    index, unmapped, no_version = _classify_osv_packages(packages)
    queries = [_osv_query_for(pkg) for pkg in index]
    return queries, index, unmapped + no_version


def _parse_osv_results(
    index: List[DependencyNode], results: List[Dict[str, Any]]
) -> List[SecurityVulnerability]:
    """把 OSV querybatch 响应映射为 SecurityVulnerability 列表。

    results 与 index 等长对齐：results[k] 对应 index[k] 这个包的查询结果。
    """
    vulns: List[SecurityVulnerability] = []
    for k, pkg in enumerate(index):
        result = results[k] if k < len(results) else {}
        if not isinstance(result, dict):
            continue
        for v in result.get("vulns", []) or []:
            parsed = _parse_one_osv_vuln(v, pkg)
            if parsed is not None:
                vulns.append(parsed)
    return vulns


def _parse_one_osv_vuln(
    vuln: Dict[str, Any], pkg: DependencyNode
) -> Optional[SecurityVulnerability]:
    """解析单个 OSV vuln → SecurityVulnerability。

    提取：CVE id（优先 CVE 别名）、CVSS v3 vector + base score、severity 档位、
    fixed_version（来自 affected[].ranges[].events[].fixed）、references。
    """
    if not isinstance(vuln, dict):
        return None

    # 1. cve_id：优先 CVE 别名，否则用 OSV id（如 GHSA-*）
    cve_id = vuln.get("id", "") or ""
    for alias in vuln.get("aliases", []) or []:
        if isinstance(alias, str) and alias.upper().startswith("CVE-"):
            cve_id = alias
            break

    # 2. CVSS v3 vector：从 severity[] 取首个 CVSS:3.x
    cvss_vector: Optional[str] = None
    for entry in vuln.get("severity", []) or []:
        if not isinstance(entry, dict):
            continue
        score = entry.get("score")
        if isinstance(score, str) and score.startswith("CVSS:3"):
            cvss_vector = score
            break

    # 3. CVSS base score：优先解析 vector（真实计算），否则回退 database_specific.cvss
    cvss_score: Optional[float] = None
    if cvss_vector:
        parsed = parse_cvss_v3_base_score(cvss_vector)
        if parsed is not None:
            cvss_score = parsed
    if cvss_score is None:
        ds = vuln.get("database_specific") or {}
        cvss_field = ds.get("cvss") if isinstance(ds, dict) else None
        if isinstance(cvss_field, dict):
            raw = cvss_field.get("score")
            if isinstance(raw, (int, float)) and 0 <= raw <= 10:
                cvss_score = float(raw)
        elif isinstance(cvss_field, (int, float)) and 0 <= cvss_field <= 10:
            cvss_score = float(cvss_field)

    # 4. severity 档位：CVSS 数值 → 标准 CVSS 分档；无数值时回退文本
    if cvss_score is not None:
        severity = _severity_from_cvss(cvss_score)
    else:
        ds = vuln.get("database_specific") or {}
        sev_text = (ds.get("severity", "") if isinstance(ds, dict) else "").upper()
        sev_map = {
            "CRITICAL": SeverityLevel.CRITICAL,
            "HIGH": SeverityLevel.HIGH,
            "MODERATE": SeverityLevel.MEDIUM,
            "MEDIUM": SeverityLevel.MEDIUM,
            "LOW": SeverityLevel.LOW,
        }
        # 无 CVSS 时默认 MEDIUM（不谎称 low 以免低估）
        severity = sev_map.get(sev_text, SeverityLevel.MEDIUM)

    # 5. fixed_version：扫描 affected[].ranges[].events[].fixed 取首个
    fixed_version: Optional[str] = None
    for aff in vuln.get("affected", []) or []:
        if not isinstance(aff, dict):
            continue
        for rng in aff.get("ranges", []) or []:
            if not isinstance(rng, dict):
                continue
            for ev in rng.get("events", []) or []:
                if isinstance(ev, dict) and ev.get("fixed"):
                    fixed_version = str(ev["fixed"])
                    break
            if fixed_version:
                break
        if fixed_version:
            break

    # 6. references + aliases
    references: List[str] = []
    for ref in vuln.get("references", []) or []:
        if isinstance(ref, dict) and isinstance(ref.get("url"), str):
            references.append(ref["url"])
    aliases: List[str] = [
        a for a in vuln.get("aliases", []) or [] if isinstance(a, str) and a
    ]

    description = vuln.get("summary") or vuln.get("details") or ""

    return SecurityVulnerability(
        package=pkg.name,
        version=pkg.version,
        severity=severity,
        cve_id=cve_id,
        description=description,
        fixed_version=fixed_version,
        references=references,
        cvss_vector=cvss_vector,
        cvss_score=cvss_score,
        aliases=aliases,
    )


class DependencyGraphDB:
    """基于 Ladybug 的依赖关系图数据库"""

    def __init__(self, db_path: Optional[str] = None):
        """
        初始化图数据库

        Args:
            db_path: 数据库文件路径，None 则使用临时文件
        """
        if db_path is None:
            temp_dir = tempfile.mkdtemp(prefix="ladybug_dep_")
            db_path = str(Path(temp_dir) / "deps.db")

        # 确保父目录存在
        db_path_obj = Path(db_path)
        db_path_obj.parent.mkdir(parents=True, exist_ok=True)

        self.db_path = db_path
        self.db = lb.Database(db_path)
        self.conn = lb.Connection(self.db)
        self._init_schema()

    def _init_schema(self):
        """初始化图数据库模式"""
        # 创建包节点表（使用 name 作为主键，version 和 ecosystem 作为属性）
        self.conn.execute("""
            CREATE NODE TABLE Package(
                name STRING, 
                version STRING, 
                ecosystem STRING,
                is_root BOOL,
                description STRING,
                license STRING,
                homepage STRING,
                download_count INT64,
                PRIMARY KEY (name)
            )
        """)

        # 创建依赖关系表
        self.conn.execute("""
            CREATE REL TABLE DependsOn(
                FROM Package TO Package,
                constraint STRING,
                edge_type STRING,
                is_optional BOOL
            )
        """)

        # 创建冲突关系表
        self.conn.execute("""
            CREATE REL TABLE ConflictsWith(
                FROM Package TO Package,
                reason STRING,
                severity STRING
            )
        """)

        # 创建漏洞表
        self.conn.execute("""
            CREATE NODE TABLE Vulnerability(
                cve_id STRING,
                package STRING,
                affected_version STRING,
                severity STRING,
                description STRING,
                fixed_version STRING,
                cvss_vector STRING,
                cvss_score DOUBLE,
                aliases STRING,
                PRIMARY KEY (cve_id)
            )
        """)

        # 创建漏洞影响关系
        self.conn.execute("""
            CREATE REL TABLE Affects(
                FROM Vulnerability TO Package
            )
        """)

    def add_package(self, package: DependencyNode) -> bool:
        """
        添加包节点

        Args:
            package: 包节点信息

        Returns:
            是否成功
        """
        try:
            is_root = "TRUE" if package.is_root else "FALSE"
            downloads = package.properties.get("downloads", 0)

            # 使用参数化查询防止 SQL 注入
            self.conn.execute(
                """
                CREATE (p:Package {
                    name: $name, 
                    version: $version, 
                    ecosystem: $ecosystem,
                    is_root: $is_root,
                    description: $description, 
                    license: $license, 
                    homepage: $homepage, 
                    download_count: $downloads
                })
            """,
                {
                    "name": package.name,
                    "version": package.version,
                    "ecosystem": package.ecosystem,
                    "is_root": package.is_root,
                    "description": package.properties.get("description", ""),
                    "license": package.properties.get("license", ""),
                    "homepage": package.properties.get("homepage", ""),
                    "downloads": downloads,
                },
            )
            return True
        except Exception as e:
            logger.error(f"添加包失败 {package.name}@{package.version}: {e}")
            return False

    def add_dependency(self, edge: DependencyEdge) -> bool:
        """
        添加依赖关系

        Args:
            edge: 依赖边信息

        Returns:
            是否成功
        """
        try:
            is_optional = edge.edge_type == "optional"

            # 使用参数化查询防止 SQL 注入
            self.conn.execute(
                """
                MATCH (s:Package {name: $source}), (t:Package {name: $target})
                CREATE (s)-[:DependsOn {
                    constraint: $constraint,
                    edge_type: $edge_type,
                    is_optional: $is_optional
                }]->(t)
            """,
                {
                    "source": edge.source,
                    "target": edge.target,
                    "constraint": edge.constraint,
                    "edge_type": edge.edge_type,
                    "is_optional": is_optional,
                },
            )
            return True
        except Exception as e:
            logger.error(f"添加依赖失败 {edge.source} -> {edge.target}: {e}")
            return False

    def add_conflict(self, pkg1: str, pkg2: str, reason: str, severity: str) -> bool:
        """添加冲突关系"""
        try:
            # 使用参数化查询防止 SQL 注入
            self.conn.execute(
                """
                MATCH (p1:Package), (p2:Package)
                WHERE p1.name = $pkg1 AND p2.name = $pkg2
                CREATE (p1)-[:ConflictsWith {
                    reason: $reason,
                    severity: $severity
                }]->(p2)
            """,
                {"pkg1": pkg1, "pkg2": pkg2, "reason": reason, "severity": severity},
            )
            return True
        except Exception as e:
            logger.error(f"添加冲突失败: {e}")
            return False

    def add_vulnerability(self, vuln: SecurityVulnerability) -> bool:
        """添加安全漏洞"""
        try:
            # 使用参数化查询防止 SQL 注入
            self.conn.execute(
                """
                CREATE (v:Vulnerability {
                    cve_id: $cve_id,
                    package: $package,
                    affected_version: $affected_version,
                    severity: $severity,
                    description: $description,
                    fixed_version: $fixed_version,
                    cvss_vector: $cvss_vector,
                    cvss_score: $cvss_score,
                    aliases: $aliases
                })
            """,
                {
                    "cve_id": vuln.cve_id,
                    "package": vuln.package,
                    "affected_version": vuln.version,
                    "severity": vuln.severity.value,
                    "description": vuln.description,
                    "fixed_version": vuln.fixed_version or "",
                    "cvss_vector": vuln.cvss_vector or "",
                    "cvss_score": vuln.cvss_score
                    if vuln.cvss_score is not None
                    else -1.0,
                    "aliases": ",".join(vuln.aliases or []),
                },
            )

            # 无论是否有 fixed_version，都必须建立 Affects 关系
            # 否则 assess_security (MATCH (v)-[:Affects]->(p)) 会漏掉无 fix 的漏洞
            self.conn.execute(
                """
                MATCH (v:Vulnerability {cve_id: $cve_id}),
                      (p:Package {name: $package})
                CREATE (v)-[:Affects]->(p)
            """,
                {"cve_id": vuln.cve_id, "package": vuln.package},
            )
            return True
        except Exception as e:
            logger.error(f"添加漏洞失败: {e}")
            return False

    def query_dependencies(self, package_name: str) -> List[Dict[str, Any]]:
        """
        查询包的依赖

        Args:
            package_name: 包名

        Returns:
            依赖列表
        """
        try:
            # 使用参数化查询防止 SQL 注入
            result = self.conn.execute(
                """
                MATCH (p:Package)-[d:DependsOn]->(dep:Package)
                WHERE p.name = $name
                RETURN p.name, p.version, dep.name, dep.version, 
                       d.constraint, d.edge_type
            """,
                {"name": package_name},
            )

            deps = []
            while result.has_next():
                row = result.get_next()
                deps.append(
                    {
                        "source": row[0],
                        "source_version": row[1],
                        "target": row[2],
                        "target_version": row[3],
                        "constraint": row[4],
                        "edge_type": row[5],
                    }
                )
            return deps
        except Exception as e:
            logger.error(f"查询依赖失败: {e}")
            return []

    def query_dependents(self, package_name: str) -> List[Dict[str, Any]]:
        """查询哪些包依赖指定包"""
        try:
            # 使用参数化查询防止 SQL 注入
            result = self.conn.execute(
                """
                MATCH (p:Package)-[d:DependsOn]->(dep:Package)
                WHERE dep.name = $name
                RETURN p.name, p.version, dep.name, dep.version, d.constraint
            """,
                {"name": package_name},
            )

            dependents = []
            while result.has_next():
                row = result.get_next()
                dependents.append(
                    {
                        "source": row[0],
                        "source_version": row[1],
                        "target": row[2],
                        "target_version": row[3],
                        "constraint": row[4],
                    }
                )
            return dependents
        except Exception as e:
            logger.error(f"查询依赖者失败: {e}")
            return []

    def find_path(self, from_pkg: str, to_pkg: str) -> List[List[str]]:
        """查找两个包之间的依赖路径"""
        try:
            # 使用参数化查询防止 SQL 注入
            result = self.conn.execute(
                """
                MATCH path = (p1:Package {name: $from})-[:DependsOn*]->(p2:Package {name: $to})
                RETURN path
                LIMIT $limit
            """,
                {"from": from_pkg, "to": to_pkg, "limit": MAX_PATHS_FIND},
            )

            paths = []
            while result.has_next():
                row = result.get_next()
                paths.append(row[0])
            return paths
        except Exception as e:
            logger.error(f"查找路径失败: {e}")
            return []

    def detect_cycles(self) -> List[List[str]]:
        """检测循环依赖"""
        try:
            result = self.conn.execute(
                """
                MATCH path = (p:Package)-[:DependsOn*]->(p)
                RETURN path
                LIMIT $limit
            """,
                {"limit": MAX_CYCLES_DETECT},
            )

            cycles = []
            while result.has_next():
                row = result.get_next()
                cycles.append(row[0])
            return cycles
        except Exception as e:
            logger.error(f"检测循环依赖失败: {e}")
            return []

    def get_graph_stats(self) -> Dict[str, Any]:
        """获取图统计信息"""
        try:
            pkg_count = self.conn.execute("MATCH (p:Package) RETURN COUNT(p)")
            dep_count = self.conn.execute("MATCH ()-[:DependsOn]->() RETURN COUNT(*)")
            conflict_count = self.conn.execute(
                "MATCH ()-[:ConflictsWith]->() RETURN COUNT(*)"
            )
            vuln_count = self.conn.execute("MATCH (v:Vulnerability) RETURN COUNT(v)")

            return {
                "total_packages": pkg_count.get_next()[0],
                "total_dependencies": dep_count.get_next()[0],
                "total_conflicts": conflict_count.get_next()[0],
                "total_vulnerabilities": vuln_count.get_next()[0],
            }
        except Exception as e:
            logger.error(f"获取统计信息失败: {e}")
            return {}

    def set_license(self, package_name: str, license_str: str) -> bool:
        """回写包的 license 到图 DB（license 的单一存储点，见 enrich_licenses）。

        Args:
            package_name: 包名（Package 主键）
            license_str: license 串；未获取到时为空串（数据层"无数据"语义）

        Returns:
            是否成功
        """
        try:
            self.conn.execute(
                """
                MATCH (p:Package {name: $name})
                SET p.license = $license
                """,
                {"name": package_name, "license": license_str},
            )
            return True
        except Exception as e:
            logger.error(f"回写 license 失败 {package_name}: {e}")
            return False

    def get_license_map(self) -> Dict[str, str]:
        """读取全部包的 license（name -> license 串，未回写的为空串）。"""
        try:
            result = self.conn.execute("MATCH (p:Package) RETURN p.name, p.license")
            licenses: Dict[str, str] = {}
            while result.has_next():
                name, lic = result.get_next()
                licenses[name] = lic or ""
            return licenses
        except Exception as e:
            logger.error(f"读取 license 失败: {e}")
            return {}

    def close(self):
        """关闭数据库连接"""
        try:
            self.conn.close()
        except Exception as e:
            logger.warning(f"关闭 Connection 失败: {e}")
        try:
            self.db.close()
        except Exception as e:
            logger.warning(f"关闭 Database 失败: {e}")


class DependencyAnalyzer:
    """依赖分析器"""

    def __init__(
        self,
        db_path: Optional[str] = None,
        http_client: Optional[RequestClient] = None,
        license_fetcher: Optional[Any] = None,
    ):
        """
        初始化分析器

        Args:
            db_path: 数据库路径
            http_client: 可选 HTTP 客户端（测试注入 mock 避免联网）；
                         默认新建 RequestClient（含重试 + 随机延迟）
            license_fetcher: 可选 license 查询器（需有 fetch(name, ecosystem)
                         -> dict，可选 fetch_many；见 enrich_licenses）。
                         None 时内部构造 EcosystemFetcher。测试注入 mock 避免联网。
        """
        self.db = DependencyGraphDB(db_path)
        self._http = http_client or RequestClient(timeout=30.0)
        self._license_fetcher = license_fetcher
        # license 是否已采集回写 DB（见 _collect_license_info，每 analyzer 只采一次）
        self._license_enriched = False
        # 豁免清单（R7）：load_exemptions 产出，assess_security 消费；
        # ignored_vulnerabilities 保存最近一次过滤结果供报告显性列出
        self.exemptions: List[Any] = []
        self.ignored_vulnerabilities: List[Dict[str, str]] = []
        # OSV 漏洞扫描状态：未扫描时显式标注，禁止静默谎报"无漏洞"
        self.osv_scan_status: Dict[str, Any] = {
            "scanned": False,
            "reason": "未执行扫描",
        }

    def _check_and_add_vulnerabilities(self, packages: List[DependencyNode]):
        """查询 OSV 批量 API 检查每个包的真实漏洞并写入图。

        失败时显式记录 osv_scan_status（标注"未扫描"），不静默、不注入假漏洞。
        无网络/超时/解析失败都属于这条显式失败路径。
        无确定版本的包被跳过时，跳过列表同样显式记录进 osv_scan_status，
        由 generate_report 转入 scan_warnings 报告（禁止静默跳过）。
        """
        if not packages:
            self.osv_scan_status = {"scanned": True, "found": 0, "skipped": []}
            return
        try:
            vulns, skipped, inferred_count = self._query_osv_batch(packages)
        except Exception as e:
            reason = f"OSV 漏洞扫描失败：{type(e).__name__}: {e}"
            logger.warning(
                reason + "（漏洞列表可能不完整；报告 scan_warnings 将显式标注）"
            )
            self.osv_scan_status = {
                "scanned": False,
                "reason": reason,
                "packages": [f"{p.name}@{p.version}" for p in packages],
            }
            return
        self.osv_scan_status = {
            "scanned": True,
            "found": len(vulns),
            "skipped": skipped,
            "inferred_count": inferred_count,
        }
        for vuln in vulns:
            self.db.add_vulnerability(vuln)

    def _query_osv_batch(
        self, packages: List[DependencyNode]
    ) -> Tuple[List[SecurityVulnerability], Dict[str, List[str]], int]:
        """批量查询 OSV (https://api.osv.dev/v1/querybatch)。

        - ecosystem 映射: pypi→PyPI / npm→npm / maven→Maven / crates→crates.io
          / rubygems→RubyGems / packagist→Packagist / nuget→NuGet
        - 提交 package + version，由 OSV 服务端做版本过滤（仅返回受影响漏洞）
        - 复用 utils.RequestClient 的重试 + 随机延迟限流
        - 分片提交，每片 OSV_BATCH_CHUNK 个包

        Returns:
            (vulns, skipped, inferred_count) 三元组：
            - vulns: 解析出的漏洞列表
            - skipped: 按原因分桶的被跳过包描述
              {"unmapped_ecosystem": [...], "no_version": [...]}
            - inferred_count: 以推断下界版本提交查询的包数（结果为保守近似）

        Raises:
            httpx.HTTPError / ValueError: 网络/HTTP/JSON 解析失败时抛出
        """
        index, unmapped, no_version = _classify_osv_packages(packages)
        skipped: Dict[str, List[str]] = {
            "unmapped_ecosystem": unmapped,
            "no_version": no_version,
        }
        skipped_total = len(unmapped) + len(no_version)
        if skipped_total:
            logger.info(
                f"OSV 跳过 {skipped_total} 个包"
                f"（生态系统未映射 {len(unmapped)} 个 / 无确定版本 {len(no_version)} 个）:"
                f" {skipped}"
            )
        if not index:
            return [], skipped, 0

        queries = [_osv_query_for(pkg) for pkg in index]
        all_results: List[Dict[str, Any]] = []
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        for i in range(0, len(queries), OSV_BATCH_CHUNK):
            chunk = queries[i : i + OSV_BATCH_CHUNK]
            response = self._http.post(
                OSV_BATCH_URL, json={"queries": chunk}, headers=headers
            )
            data = response.json()
            if not isinstance(data, dict):
                raise ValueError(f"OSV 响应非 JSON 对象: {type(data).__name__}")
            chunk_results = data.get("results", [])
            if not isinstance(chunk_results, list):
                raise ValueError("OSV 响应 results 字段非列表")
            # 对齐：OSV 规范保证 results 与 queries 等长（无漏洞的为 {}）
            all_results.extend(chunk_results)
            # 翻页：next_page_token 表示同一批查询还有更多漏洞
            page_token = data.get("next_page_token")
            while page_token:
                body = {"queries": chunk, "page_token": page_token}
                response = self._http.post(OSV_BATCH_URL, json=body, headers=headers)
                data = response.json()
                page_results = data.get("results", [])
                for j, pr in enumerate(page_results):
                    base = i + j
                    if base < len(all_results):
                        all_results[base].setdefault("vulns", []).extend(
                            pr.get("vulns", []) if isinstance(pr, dict) else []
                        )
                page_token = data.get("next_page_token")

        inferred_count = sum(1 for p in index if p.version_inferred)
        return _parse_osv_results(index, all_results), skipped, inferred_count

    def build_dependency_graph(
        self, packages: List[DependencyNode], dependencies: List[DependencyEdge]
    ) -> bool:
        """
        构建依赖关系图

        Args:
            packages: 包节点列表
            dependencies: 依赖边列表

        Returns:
            是否成功
        """
        logger.info(
            f"正在构建依赖图: {len(packages)} 个包, {len(dependencies)} 个依赖关系"
        )

        # 添加所有包节点
        for pkg in packages:
            self.db.add_package(pkg)

        # 添加所有依赖关系
        for dep in dependencies:
            self.db.add_dependency(dep)

        # 添加已知漏洞
        self._check_and_add_vulnerabilities(packages)

        logger.info("依赖图构建完成")
        return True

    def detect_conflicts(self) -> List[ConflictInfo]:
        """
        检测依赖冲突

        Returns:
            冲突列表
        """
        logger.info("检测依赖冲突...")
        conflicts = []

        # 查询所有包 - 使用参数化查询
        result = self.db.conn.execute("MATCH (p:Package) RETURN p.name, p.version")
        packages = {}
        while result.has_next():
            row = result.get_next()
            pkg_name = row[0]
            if pkg_name not in packages:
                packages[pkg_name] = []
            packages[pkg_name].append(row[1])

        # 检查每个包是否有版本冲突
        for pkg_name, versions in packages.items():
            if len(versions) > 1:
                # 查询谁依赖这些版本
                dependents = self.db.query_dependents(pkg_name)

                # 检查约束是否冲突
                constraints = defaultdict(list)
                for dep in dependents:
                    constraints[dep["constraint"]].append(dep["source"])

                # 如果有多个不同的约束，可能冲突
                if len(constraints) > 1:
                    conflict = ConflictInfo(
                        package=pkg_name,
                        required_by=[
                            {"package": pkg, "constraint": c}
                            for c, pkgs in constraints.items()
                            for pkg in pkgs
                        ],
                        conflict_type="version_mismatch",
                        severity=SeverityLevel.HIGH,
                        suggestion=f"统一 {pkg_name} 的版本约束",
                    )
                    conflicts.append(conflict)

        logger.info(f"发现 {len(conflicts)} 个冲突")
        return conflicts

    def recommend_optimal_versions(self) -> Dict[str, str]:
        """
        推荐最优版本

        Returns:
            包名 -> 推荐版本的映射
        """
        logger.info("计算最优版本推荐...")
        recommendations = {}

        # 查询所有包及其约束 - 使用参数化查询
        result = self.db.conn.execute("""
            MATCH (p:Package)-[d:DependsOn]->(dep:Package)
            RETURN p.name, dep.name, d.constraint
        """)

        constraints = defaultdict(list)
        all_versions = defaultdict(set)

        # 收集所有约束
        while result.has_next():
            row = result.get_next()
            target_pkg = row[1]
            constraint = row[2]
            constraints[target_pkg].append(constraint)

            # 获取所有可用版本 - 使用参数化查询
            ver_result = self.db.conn.execute(
                """
                MATCH (p:Package) WHERE p.name = $name
                RETURN p.version
            """,
                {"name": target_pkg},
            )
            while ver_result.has_next():
                all_versions[target_pkg].add(ver_result.get_next()[0])

        # 为每个包找到满足所有约束的最优版本
        for pkg_name, pkg_constraints in constraints.items():
            versions = list(all_versions.get(pkg_name, []))
            if not versions:
                continue

            # 找到满足所有约束的版本
            valid_versions = []
            for version in versions:
                if all(check_version_constraint(version, c) for c in pkg_constraints):
                    valid_versions.append(version)

            if valid_versions:
                # 选择最新版本
                sorted_versions = sort_versions(valid_versions, reverse=True)
                recommendations[pkg_name] = sorted_versions[0]
            else:
                # 没有完全满足的版本，选择满足最多约束的最新版本
                recommendations[pkg_name] = self._find_best_compromise(
                    versions, pkg_constraints
                )

        logger.info(f"生成 {len(recommendations)} 个版本推荐")
        return recommendations

    def _find_best_compromise(self, versions: List[str], constraints: List[str]) -> str:
        """找到最佳妥协版本"""
        best_version = versions[0]
        max_satisfied = 0

        for version in versions:
            satisfied = sum(
                1 for c in constraints if check_version_constraint(version, c)
            )
            if satisfied > max_satisfied:
                max_satisfied = satisfied
                best_version = version

        return best_version

    def assess_security(self) -> List[SecurityVulnerability]:
        """
        评估依赖安全性

        Returns:
            漏洞列表
        """
        logger.info("评估依赖安全性...")

        result = self.db.conn.execute("""
            MATCH (v:Vulnerability)-[:Affects]->(p:Package)
            RETURN v.cve_id, v.package, v.affected_version,
                   v.severity, v.description, v.fixed_version,
                   v.cvss_vector, v.cvss_score, v.aliases
        """)

        vulnerabilities = []
        while result.has_next():
            row = result.get_next()
            cvss_score = row[7]
            vuln = SecurityVulnerability(
                cve_id=row[0],
                package=row[1],
                version=row[2],
                severity=SeverityLevel(row[3]),
                description=row[4],
                fixed_version=row[5] if row[5] else None,
                cvss_vector=row[6] if row[6] else None,
                cvss_score=cvss_score
                if isinstance(cvss_score, (int, float)) and cvss_score >= 0
                else None,
                aliases=[a for a in (row[8] or "").split(",") if a],
            )
            vulnerabilities.append(vuln)

        # 豁免清单过滤（R7）：被豁免的漏洞转入 ignored_vulnerabilities 显性列出，
        # 不静默消失；过期豁免自动失效（留在 vulnerabilities 恢复告警）
        self.ignored_vulnerabilities = []
        if self.exemptions:
            import exemptions as exemptions_mod

            vulnerabilities, self.ignored_vulnerabilities = (
                exemptions_mod.apply_exemptions(vulnerabilities, self.exemptions)
            )
            if self.ignored_vulnerabilities:
                logger.info(
                    f"豁免清单生效：{len(self.ignored_vulnerabilities)} 个漏洞被过滤"
                    f"（报告 ignored_vulnerabilities 段可见明细）"
                )

        logger.info(f"发现 {len(vulnerabilities)} 个安全漏洞")
        return vulnerabilities

    def plan_update_paths(self) -> List[UpdatePath]:
        """
        规划更新路径

        Returns:
            更新路径列表
        """
        logger.info("规划更新路径...")
        update_paths = []

        # 获取所有需要更新的包（有漏洞或版本过旧）
        result = self.db.conn.execute("""
            MATCH (v:Vulnerability)-[:Affects]->(p:Package)
            WHERE v.fixed_version IS NOT NULL
            RETURN p.name, p.version, v.fixed_version, v.cve_id
        """)

        updates = {}
        while result.has_next():
            row = result.get_next()
            pkg_name = row[0]
            current_ver = row[1]
            fixed_ver = row[2]

            if pkg_name not in updates:
                updates[pkg_name] = {
                    "current": current_ver,
                    "target": fixed_ver,
                    "reasons": [],
                }
            updates[pkg_name]["reasons"].append(f"修复 {row[3]}")

        # 生成更新路径
        for pkg_name, info in updates.items():
            path = UpdatePath(
                package=pkg_name,
                current_version=info["current"],
                target_version=info["target"],
                steps=[
                    f"当前版本: {info['current']}",
                    f"目标版本: {info['target']}",
                    f"原因: {', '.join(info['reasons'])}",
                    "建议: 在测试环境验证后更新",
                ],
                breaking_changes=[],
                recommendation=f"建议更新到 {info['target']} 以修复安全问题",
            )
            update_paths.append(path)

        logger.info(f"生成 {len(update_paths)} 条更新路径")
        return update_paths

    def generate_report(self, root_package: str) -> AnalysisReport:
        """
        生成完整分析报告

        Args:
            root_package: 根包名

        Returns:
            分析报告
        """
        logger.info(f"生成依赖分析报告: {root_package}")

        # 收集所有分析结果
        conflicts = self.detect_conflicts()
        recommendations = self.recommend_optimal_versions()
        vulnerabilities = self.assess_security()
        update_paths = self.plan_update_paths()

        # 获取图统计
        stats = self.db.get_graph_stats()

        # 生成建议
        recommendations_list = []
        if conflicts:
            recommendations_list.append(
                f"发现 {len(conflicts)} 个依赖冲突，建议统一版本约束"
            )
        if vulnerabilities:
            recommendations_list.append(
                f"发现 {len(vulnerabilities)} 个安全漏洞，建议尽快更新"
            )
        if update_paths:
            recommendations_list.append(
                f"有 {len(update_paths)} 个包可以更新到更安全的版本"
            )

        # 显式收集漏洞扫描状态告警（OSV 失败时不得静默谎报"无漏洞"）
        scan_warnings: List[str] = []
        status = self.osv_scan_status
        skipped = (status or {}).get("skipped", {})
        # skipped 按跳过原因分桶（生态未映射 ≠ 无确定版本，文案不得混桶）
        unmapped = skipped.get("unmapped_ecosystem", []) if isinstance(skipped, dict) else []
        no_version = skipped.get("no_version", []) if isinstance(skipped, dict) else []
        if unmapped:
            scan_warnings.append(
                f"漏洞扫描跳过 {len(unmapped)} 个生态系统未映射的包"
                f"（OSV 不支持该生态，未查询）：{unmapped}"
            )
        if no_version:
            scan_warnings.append(
                f"漏洞扫描跳过 {len(no_version)} 个无确定版本的包"
                f"（范围/通配约束无法定位具体版本，未查询 OSV）：{no_version}"
            )
        inferred_count = (status or {}).get("inferred_count", 0)
        if inferred_count:
            scan_warnings.append(
                f"漏洞扫描对 {inferred_count} 个包使用范围约束推断的下界版本"
                f"（如 ^1.2.0 → 1.2.0），受影响判定为保守近似"
            )
        if status and not status.get("scanned"):
            pkg_list = status.get("packages", [])
            scan_warnings.append(
                f"安全漏洞扫描未完成：{status.get('reason', '未知原因')}。"
                f"漏洞列表可能不完整（涉及 {len(pkg_list)} 个包），"
                f"请检查网络后重试或人工核查。"
            )

        # 采集依赖许可证（健康度"许可证合规"维度的真实数据源；
        # 查询失败的包以 UNKNOWN 显式标注，不静默留空）
        license_info = self._collect_license_info()

        report = AnalysisReport(
            timestamp=time.time(),
            root_package=root_package,
            total_packages=stats.get("total_packages", 0),
            total_edges=stats.get("total_dependencies", 0),
            conflicts=conflicts,
            vulnerabilities=vulnerabilities,
            update_paths=update_paths,
            recommendations=recommendations_list,
            graph_stats=stats,
            scan_warnings=scan_warnings,
            license_info=license_info,
            ignored_vulnerabilities=list(self.ignored_vulnerabilities),
        )

        return report

    def _collect_license_info(self) -> List[Dict[str, str]]:
        """从图 DB 读取全部非根包 license（license 的单一存储点是 Package.license）。

        DB 尚无 license 数据时（本 analyzer 首次生成报告），先用 license_fetcher
        采集一次并回写 DB（enrich_licenses），再从 DB 读——保证返回值永远是
        DB 存储值而非临时节点属性。DB 中为空串（查询失败/registry 未返回）
        的包在报告层以 "UNKNOWN" 显式标注，禁止静默留空。

        Returns:
            license_info 列表（供 report_to_dict 输出、健康度评分消费）
        """
        if not self._license_enriched:
            nodes: List[DependencyNode] = []
            result = self.db.conn.execute(
                "MATCH (p:Package) RETURN p.name, p.ecosystem, p.is_root"
            )
            while result.has_next():
                name, eco, is_root = result.get_next()
                nodes.append(
                    DependencyNode(
                        name=name, version="", ecosystem=eco, is_root=bool(is_root)
                    )
                )
            enrich_licenses(nodes, fetcher=self._license_fetcher, db=self.db)
            self._license_enriched = True

        result = self.db.conn.execute(
            """
            MATCH (p:Package) WHERE p.is_root = $is_root
            RETURN p.name, p.license
            """,
            {"is_root": False},
        )
        license_info: List[Dict[str, str]] = []
        while result.has_next():
            name, lic = result.get_next()
            license_info.append({"package": name, "license": lic or "UNKNOWN"})
        return license_info

    def report_to_dict(self, report: AnalysisReport) -> Dict[str, Any]:
        """将 AnalysisReport 转换为 dict（供 JSON/HTML/PDF 渲染用）"""
        return {
            "timestamp": report.timestamp,
            "root_package": report.root_package,
            "summary": {
                "total_packages": report.total_packages,
                "total_dependencies": report.total_edges,
                "conflicts": len(report.conflicts),
                "vulnerabilities": len(report.vulnerabilities),
                "update_paths": len(report.update_paths),
            },
            "conflicts": [
                {
                    "package": c.package,
                    "conflict_type": c.conflict_type,
                    "severity": c.severity.value,
                    "required_by": c.required_by,
                    "suggestion": c.suggestion,
                }
                for c in report.conflicts
            ],
            "vulnerabilities": [
                {
                    "cve_id": v.cve_id,
                    "package": v.package,
                    "version": v.version,
                    "severity": v.severity.value,
                    "description": v.description,
                    "fixed_version": v.fixed_version,
                    "cvss_vector": v.cvss_vector,
                    "cvss_score": v.cvss_score,
                }
                for v in report.vulnerabilities
            ],
            "update_paths": [
                {
                    "package": p.package,
                    "current_version": p.current_version,
                    "target_version": p.target_version,
                    "steps": p.steps,
                    "recommendation": p.recommendation,
                }
                for p in report.update_paths
            ],
            "recommendations": report.recommendations,
            "scan_warnings": report.scan_warnings,
            "license_info": report.license_info,
            "ignored_vulnerabilities": report.ignored_vulnerabilities,
        }

    def export_report_json(self, report: AnalysisReport, output_file: str):
        """导出报告为 JSON"""
        report_dict = self.report_to_dict(report)

        output_path = Path(output_file)
        with output_path.open("w", encoding="utf-8") as f:
            json.dump(report_dict, f, indent=2, ensure_ascii=False)

        logger.info(f"报告已导出: {output_file}")

    def close(self):
        """关闭数据库"""
        try:
            self.db.close()
        except Exception as e:
            logger.error(f"关闭数据库时出错: {e}")


def detect_dependency_file(project_path: str) -> Optional[str]:
    """
    自动检测项目中的依赖文件

    Args:
        project_path: 项目路径

    Returns:
        依赖文件路径，如果未找到返回 None
    """
    # 文件 → 生态映射来自单一注册表（manifest + lockfile 全集）
    dependency_files = eco_reg.detect_files()

    path_obj = Path(project_path)

    # 如果传入的是文件路径
    if path_obj.is_file():
        filename = path_obj.name
        if filename in dependency_files:
            return str(path_obj)
        # 按扩展名匹配（如 MyApp.csproj）
        if eco_reg.extension_entry(path_obj.suffix):
            return str(path_obj)
        logger.warning(f"不支持的依赖文件格式 {filename}")
        return None

    # 如果传入的是目录，扫描查找依赖文件
    if path_obj.is_dir():
        # 先收集目录下所有生态的依赖文件（用于多生态共存时的显式提示，规则12：
        # 静默缩小扫描范围是禁止的——生效/跳过清单必须展示）
        detected: List[tuple] = []
        for filename, ecosystem in dependency_files.items():
            filepath = path_obj / filename
            if filepath.exists():
                detected.append((ecosystem, filename, filepath))
        for filepath in sorted(path_obj.iterdir()):
            if filepath.is_file():
                ecosystem = eco_reg.extension_entry(filepath.suffix)
                if ecosystem:
                    detected.append((ecosystem, filepath.name, filepath))

        if detected:
            for eco, name, _ in detected:
                logger.info(f"检测到 {eco} 项目: {name}")
            # 同生态 lockfile 优先于 manifest（精确锁定版本 > 范围约束下界）；
            # 被跳过的 manifest 显性列出（规则 12：静默缩小范围禁止）
            lockfile_first = [
                d for d in detected
                if (eco_reg.file_entry(d[1]) or {}).get("kind") == "lockfile"
            ]
            if lockfile_first:
                chosen = lockfile_first[0]
                rest = [d for d in detected if d[1] != chosen[1]]
                skipped_manifests = [
                    name for _, name, _ in rest
                    if (eco_reg.file_entry(name) or {}).get("kind") == "manifest"
                    and (eco_reg.file_entry(name) or {}).get("ecosystem") == chosen[0]
                ]
                detected = [chosen] + rest
                if skipped_manifests:
                    logger.info(
                        f"命中 lockfile {chosen[1]}，优先使用精确版本；"
                        f"同生态 manifest 跳过: {', '.join(skipped_manifests)}"
                    )
            distinct = {eco for eco, _, _ in detected}
            if len(distinct) > 1:
                effective = detected[0][1]
                skipped = ", ".join(name for _, name, _ in detected[1:])
                print(
                    f"\n⚠️ 检测到多个生态的依赖文件，本次只分析生效文件: {effective}"
                )
                print(f"   跳过: {skipped}")
                print(
                    "   如需分析其他生态，请显式指定依赖文件路径"
                    "（直接传入该文件路径）后重新运行。\n"
                )
            return str(detected[0][2])

    return None


# ============ 版本约束 → 确定版本解析（纯函数，便于离线单测） ============

# 可作为确定版本送 OSV 的版本串：1-4 段数字 + 可选 prerelease/build 元数据
_CONCRETE_VERSION_RE = re.compile(r"^\d+(?:\.\d+){0,3}(?:[-+][0-9A-Za-z.\-]+)?$")
# 完整三段裸版本（含可选 prerelease）视为精确锁定
_EXACT_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+(?:[-+].*)?$")
# 下界型操作符：约束允许集合的最小值可从字面量推断
_LOWER_BOUND_OP_RE = re.compile(r"^(?:\^|~=|~|>=|==|=)")
# 上界/排除/严格大于：字面量不在允许集合内，不得当作受检版本
_NON_MEMBER_OP_RE = re.compile(r"^(?:<=|<|!=|>)")


def _extract_concrete_version(constraint: str) -> Optional[Tuple[str, bool]]:
    """从单个版本约束提取确定版本（下界）。

    Returns:
        (version, inferred) 二元组：
        - ("1.2.3", False)：精确锁定（裸三段版本或 ==/= 约束）
        - ("1.2.0", True)：从范围约束推断的下界（^1.2.0 / ~1.2.3 / >=2.0 / ~=1.2 等）
        None：无法得到确定版本（通配 */x、区间 ||、标签 latest、workspace:/file:/
        git: 链接、纯上界 < / <=、排除 !=、严格大于 > 等）。

        调用方约定：返回 None 的包禁止编造版本（如 "0.0.0"）送 OSV 查询，
        必须跳过查询并在结果中显式报告跳过数量与原因。
    """
    if not constraint:
        return None
    text = constraint.strip()
    if not text:
        return None
    # OR 复合约束存在多个候选集合，无法取唯一下界
    if "||" in text:
        return None
    # AND 复合约束（npm 空格区间 / pip 逗号列表 / npm hyphen 区间）
    # 取首个下界段；hyphen 区间第一段同样是下界
    if re.search(r"\s-\s", text):
        segment = re.split(r"\s-\s", text, maxsplit=1)[0].strip()
        forced_inferred = True
    else:
        segment = re.split(r"[,\s]+", text, maxsplit=1)[0].strip()
        forced_inferred = False

    op_match = _LOWER_BOUND_OP_RE.match(segment)
    if op_match:
        operator = op_match.group(0)
        version = segment[op_match.end() :].strip()
        inferred = operator not in ("=", "==")
    elif _NON_MEMBER_OP_RE.match(segment):
        # < / <= / != / > 的字面量不属于允许集合，送 OSV 会得出错误结论
        return None
    else:
        version = segment
        # npm 裸两段（"1.2" ≡ 1.2.x）是 range 而非精确锁定
        inferred = not bool(_EXACT_VERSION_RE.match(version))
    if forced_inferred:
        inferred = True
    if not version or not _CONCRETE_VERSION_RE.match(version):
        return None
    return version, inferred


def parse_pyproject_toml(
    project_path: str,
) -> tuple[List[DependencyNode], List[DependencyEdge]]:
    """
    解析 pyproject.toml 文件，提取依赖信息

    Args:
        project_path: pyproject.toml 文件路径

    Returns:
        (packages, edges) 元组
    """
    try:
        import tomllib
    except ImportError:
        try:
            import tomli as tomllib
        except ImportError:
            logger.error("需要安装 tomli 库: pip install tomli")
            sys.exit(EXIT_INPUT_ERROR)

    path_obj = Path(project_path)
    if not path_obj.exists():
        logger.error(f"找不到文件 {project_path}")
        sys.exit(EXIT_INPUT_ERROR)

    # 读取并解析 TOML 文件
    try:
        with path_obj.open("rb") as f:
            data = tomllib.load(f)
    except Exception as e:
        logger.error(f"解析 TOML 文件失败: {e}")
        sys.exit(EXIT_INPUT_ERROR)

    # 提取项目名称
    project_info = data.get("project", {})
    project_name = project_info.get("name", "unknown")
    project_version = project_info.get("version", "0.1.0")

    # 提取依赖列表
    dependencies = project_info.get("dependencies", [])
    if not dependencies:
        logger.warning("未找到 dependencies 字段")
        return [], []

    packages = [
        DependencyNode(
            name=project_name, version=project_version, ecosystem="pypi", is_root=True
        )
    ]

    edges = []

    for dep_str in dependencies:
        # 跳过注释
        if dep_str.startswith("#"):
            continue

        # 解析包名和版本约束
        # 格式: package>=1.0.0 或 package==1.0.0 或 package
        # 或者: package[extra]>=1.0.0
        match = re.match(r"([a-zA-Z0-9_-]+)(?:\[.*?\])?\s*(.*)?", dep_str)
        if match:
            pkg_name = match.group(1).lower()
            constraint = match.group(2).strip() if match.group(2) else "*"

            # 提取确定版本（下界）；无法确定时留空，禁止编造版本送 OSV
            resolved = _extract_concrete_version(constraint)
            version = resolved[0] if resolved else ""

            packages.append(
                DependencyNode(
                    name=pkg_name,
                    version=version,
                    ecosystem="pypi",
                    version_inferred=resolved[1] if resolved else False,
                )
            )

            edges.append(
                DependencyEdge(
                    source=project_name, target=pkg_name, constraint=constraint
                )
            )

    return packages, edges


def parse_package_json(
    project_path: str,
) -> tuple[List[DependencyNode], List[DependencyEdge]]:
    """
    解析 package.json 文件，提取依赖信息

    Args:
        project_path: package.json 文件路径

    Returns:
        (packages, edges) 元组
    """
    path_obj = Path(project_path)
    if not path_obj.exists():
        logger.error(f"找不到文件 {project_path}")
        sys.exit(EXIT_INPUT_ERROR)

    try:
        with path_obj.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        logger.error(f"解析 JSON 文件失败: {e}")
        sys.exit(EXIT_INPUT_ERROR)

    project_name = data.get("name", "unknown")
    project_version = data.get("version", "0.1.0")

    packages = [
        DependencyNode(
            name=project_name, version=project_version, ecosystem="npm", is_root=True
        )
    ]

    edges = []

    # 合并 dependencies 和 devDependencies
    all_deps = {}
    all_deps.update(data.get("dependencies", {}))
    all_deps.update(data.get("devDependencies", {}))

    for pkg_name, version_constraint in all_deps.items():
        # 提取确定版本（下界）；无法确定（*/latest/x 通配、区间）时留空，
        # 由 OSV 查询侧跳过并在报告中显式标注，禁止编造版本
        resolved = _extract_concrete_version(version_constraint)
        version = resolved[0] if resolved else ""

        packages.append(
            DependencyNode(
                name=pkg_name,
                version=version,
                ecosystem="npm",
                version_inferred=resolved[1] if resolved else False,
            )
        )

        edges.append(
            DependencyEdge(
                source=project_name, target=pkg_name, constraint=version_constraint
            )
        )

    return packages, edges


def parse_requirements_txt(
    project_path: str,
) -> tuple[List[DependencyNode], List[DependencyEdge]]:
    """
    解析 requirements.txt 文件，提取依赖信息

    Args:
        project_path: requirements.txt 文件路径

    Returns:
        (packages, edges) 元组
    """
    path_obj = Path(project_path)
    if not path_obj.exists():
        logger.error(f"找不到文件 {project_path}")
        sys.exit(EXIT_INPUT_ERROR)

    try:
        with path_obj.open("r", encoding="utf-8") as f:
            lines = f.readlines()
    except Exception as e:
        logger.error(f"读取文件失败: {e}")
        sys.exit(EXIT_INPUT_ERROR)

    project_name = "unknown"
    packages = []
    edges = []

    for line in lines:
        line = line.strip()

        # 跳过注释和空行
        if not line or line.startswith("#") or line.startswith("-"):
            continue

        # 解析包名和版本
        match = re.match(r"([a-zA-Z0-9_-]+)\s*(.*)?", line)
        if match:
            pkg_name = match.group(1).lower()
            constraint = match.group(2).strip() if match.group(2) else "*"

            # 提取确定版本（下界）；无法确定时留空，禁止编造版本送 OSV
            resolved = _extract_concrete_version(constraint)
            version = resolved[0] if resolved else ""

            packages.append(
                DependencyNode(
                    name=pkg_name,
                    version=version,
                    ecosystem="pypi",
                    version_inferred=resolved[1] if resolved else False,
                )
            )

    return packages, edges


def parse_dependencies(
    project_path: str,
) -> tuple[List[DependencyNode], List[DependencyEdge], str]:
    """
    智能解析项目依赖，自动检测依赖文件类型

    Args:
        project_path: 项目路径或依赖文件路径

    Returns:
        (packages, edges, ecosystem) 元组
    """
    # 自动检测依赖文件
    dep_file = detect_dependency_file(project_path)

    if not dep_file:
        logger.error(f"在项目 {project_path} 中未找到支持的依赖文件")
        logger.info("支持的依赖文件（来自 ecosystem_registry）:")
        for eco, meta in eco_reg.ECOSYSTEMS.items():
            files = [
                name
                for name, entry in eco_reg.DEPENDENCY_FILES.items()
                if entry["ecosystem"] == eco
            ]
            logger.info(f"  {meta.get('display_name', eco)}({eco}): {', '.join(files)}")
        logger.info("注: Go 和 C/C++ 无中央 registry，不在支持列表")
        sys.exit(EXIT_INPUT_ERROR)

    filename = Path(dep_file).name

    # 文件 → (parser, ecosystem) 分派来自单一注册表
    entry = eco_reg.file_entry(filename)
    ext_eco = eco_reg.extension_entry(Path(filename).suffix)
    if entry is None and ext_eco:
        entry = {"ecosystem": ext_eco, "kind": "manifest", "parser": None}

    if entry is None:
        logger.warning(f"暂不支持自动解析 {filename}")
        supported = [
            name
            for name, e in eco_reg.DEPENDENCY_FILES.items()
            if e["parser"]
        ]
        logger.info(f"提示: 目前支持自动解析 {', '.join(supported)}")
        sys.exit(EXIT_INPUT_ERROR)

    ecosystem = entry["ecosystem"]

    if not entry["parser"] or entry["parser"] not in PARSER_FUNCS:
        # 检测可识别但 parser 未实现（注册表声明与实现不一致同样走这里）：
        # 显式提示替代方案，不静默失败
        logger.warning(
            f"已检测到 {filename}（ecosystem={ecosystem}，"
            f"{entry['kind']}），但自动解析器暂未实现。"
        )
        logger.info(
            f"请改用 query/search 子命令手动查询: "
            f"python dependency_analyzer.py query <pkg> -e {ecosystem}"
        )
        sys.exit(EXIT_INPUT_ERROR)

    parse_func = PARSER_FUNCS[entry["parser"]]

    logger.info(f"解析依赖文件: {filename}")
    packages, edges = parse_func(dep_file)

    if not packages:
        logger.error("未找到依赖信息")
        sys.exit(EXIT_INPUT_ERROR)

    return packages, edges, ecosystem


def display_conflicts(conflicts: List[ConflictInfo]):
    """显示依赖冲突"""
    if conflicts:
        logger.info(f"发现 {len(conflicts)} 个冲突:")
        for conflict in conflicts:
            logger.info(f"  包: {conflict.package}")
            logger.info(f"  类型: {conflict.conflict_type}")
            logger.info(f"  严重级别: {conflict.severity.value}")
            logger.info(f"  建议: {conflict.suggestion}")
    else:
        logger.info("未发现依赖冲突")


def display_recommendations(recommendations: Dict[str, str]):
    """显示版本推荐"""
    if recommendations:
        logger.info("版本推荐:")
        for pkg, version in list(recommendations.items())[:MAX_RECOMMENDATIONS_DISPLAY]:
            logger.info(f"  {pkg}: {version}")
        if len(recommendations) > MAX_RECOMMENDATIONS_DISPLAY:
            logger.info(f"  ... 共 {len(recommendations)} 个推荐")


def display_vulnerabilities(vulns: List[SecurityVulnerability]):
    """显示安全漏洞"""
    if vulns:
        logger.info(f"发现 {len(vulns)} 个安全漏洞:")
        for vuln in vulns:
            logger.info(f"  CVE: {vuln.cve_id}")
            logger.info(f"  包: {vuln.package}@{vuln.version}")
            logger.info(f"  严重级别: {vuln.severity.value}")
            logger.info(f"  描述: {vuln.description}")
            if vuln.fixed_version:
                logger.info(f"  修复版本: {vuln.fixed_version}")
    else:
        logger.info("未发现已知安全漏洞")


def display_update_paths(update_paths: List[UpdatePath]):
    """显示更新路径"""
    if update_paths:
        logger.info(f"找到 {len(update_paths)} 条更新路径:")
        for path in update_paths:
            logger.info(f"  包: {path.package}")
            logger.info(f"  当前: {path.current_version} → 目标: {path.target_version}")
            logger.info(f"  建议: {path.recommendation}")
    else:
        logger.info("无需更新")


def display_ignored_vulnerabilities(ignored: List[Dict[str, str]]) -> None:
    """显性列出被豁免的漏洞（规则 11：不静默消失，逐条带理由与过期日）。"""
    if not ignored:
        return
    print(f"\n📋 豁免清单生效：{len(ignored)} 个漏洞被过滤（明细如下）:")
    for item in ignored:
        until = f"，豁免至 {item['ignore_until']}" if item.get("ignore_until") else "，永久豁免"
        via = (
            f"（经由 alias {item['matched_via']} 命中）"
            if item.get("matched_via") and item["matched_via"] != item.get("cve_id")
            else ""
        )
        print(f"  - {item.get('cve_id', '?')} on {item.get('package', '?')}: {item.get('reason', '')}{until}{via}")


def load_exemptions_for(args, data: Dict[str, Any], data_path: Path) -> List[Any]:
    """组装 analyze-data 的豁免清单：--config 显式 > 数据文件旁/进程目录自动探测
    > deps_data 内联 ignored_vulns。配置非法显式退出（128），不静默忽略。"""
    import exemptions as exemptions_mod

    collected: List[Any] = []
    config = getattr(args, "config", None)
    if config:
        collected.extend(exemptions_mod.load_exemptions(config))
    else:
        auto = exemptions_mod.find_config_file(data_path.parent) or (
            exemptions_mod.find_config_file(Path.cwd())
        )
        if auto:
            logger.info(f"自动加载豁免配置: {auto}")
            collected.extend(exemptions_mod.load_exemptions(str(auto)))
    collected.extend(exemptions_mod.from_deps_data(data))
    return collected


def _deps_data_to_graph(data: Dict[str, Any]) -> Tuple[List[DependencyNode], List[DependencyEdge]]:
    """deps_data dict schema → (DependencyNode, DependencyEdge) 列表。

    外部入口（analyze-data / report 的 deps_data.json 由 LLM 或工具手工整理）
    的 version 字段可能是范围串/伪版本（"^1.2.0"、"1.2.x"、"*"），每个 version
    都过一遍 _extract_concrete_version 归一化：可解析取下界并标 version_inferred，
    无法确定（通配/区间/排除式）留空串——禁止伪版本原样送 OSV 查询。
    """
    packages = []
    for pkg_data in data["packages"]:
        raw_version = str(pkg_data.get("version", "") or "")
        resolved = _extract_concrete_version(raw_version)
        version_resolved = bool(pkg_data.get("version_resolved", False))
        packages.append(
            DependencyNode(
                name=pkg_data["name"],
                # 无确定版本留空（OSV 查询跳过并显式报告），禁止编造版本
                version=resolved[0] if resolved else "",
                ecosystem=pkg_data.get("ecosystem", "pypi"),
                is_root=pkg_data.get("is_root", False),
                # deps_data 显式声明 version_resolved 的包视为精确锁定
                # （如 --from-sbom 回灌的 SBOM、外部 lockfile 工具产出）
                version_inferred=(resolved[1] if resolved else False)
                and not version_resolved,
                version_resolved=version_resolved,
            )
        )

    edges = []
    for edge_data in data["edges"]:
        edges.append(
            DependencyEdge(
                source=edge_data["source"],
                target=edge_data["target"],
                constraint=edge_data.get("constraint", "*"),
            )
        )
    return packages, edges


# ============ lockfile 解析器（R4：精确版本来源，优先于 manifest） ============
# 每个 parser 返回 (packages, edges)：packages 含根节点（is_root=True，来自同目录
# manifest 或 lockfile 自身的根条目），所有非根节点 version_resolved=True 且
# version_inferred=False（精确锁定，OSV 判定不再保守近似）。


def _lockfile_root_from_toml(lock_path: Path, manifest_name: str) -> Dict[str, Any]:
    """读同目录 TOML manifest 的 project/package 段 name+version（拿不到返回 {}）。"""
    manifest = lock_path.parent / manifest_name
    if not manifest.is_file():
        return {}
    try:
        import tomllib
    except ImportError:
        import tomli as tomllib  # type: ignore
    try:
        with manifest.open("rb") as f:
            data = tomllib.load(f)
    except Exception as e:
        logger.warning(f"解析 {manifest.name} 失败（根节点信息降级）: {e}")
        return {}
    info = data.get("project") or data.get("package") or {}
    if not info.get("name"):
        return {}
    return {"name": info["name"], "version": str(info.get("version", "0.0.0"))}


def _manifest_constraints(lock_path: Path, manifest_name: str) -> Dict[str, str]:
    """读同目录 manifest 的依赖约束映射（pyproject.toml 的 [project].dependencies）。"""
    manifest = lock_path.parent / manifest_name
    if not manifest.is_file():
        return {}
    try:
        import tomllib
    except ImportError:
        import tomli as tomllib  # type: ignore
    try:
        with manifest.open("rb") as f:
            data = tomllib.load(f)
    except Exception:
        return {}
    constraints: Dict[str, str] = {}
    for dep in (data.get("project") or {}).get("dependencies", []) or []:
        m = re.match(r"([A-Za-z0-9_.-]+)(?:\[.*?\])?\s*(.*)", str(dep))
        if m:
            constraints[m.group(1).lower()] = (m.group(2) or "*").strip() or "*"
    return constraints


def _name_version(label: str) -> tuple[str, str]:
    """Cargo.lock dependencies 条目 "name" 或 "name 1.2.3" → (name, version|空)。"""
    parts = label.strip().split()
    return (parts[0], parts[1]) if len(parts) > 1 else (parts[0], "")


def parse_package_lock_json(project_path: str):
    """package-lock.json v2/v3：packages["node_modules/*"] 为精确锁定版本。"""
    path_obj = Path(project_path)
    try:
        with path_obj.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        logger.error(f"解析 JSON 文件失败: {e}")
        sys.exit(EXIT_INPUT_ERROR)

    all_entries = data.get("packages")
    if not isinstance(all_entries, dict):
        logger.error("package-lock.json 缺少 packages 字段（v1 格式请升级 lockfile 或改用 package.json）")
        sys.exit(EXIT_INPUT_ERROR)

    root_entry = all_entries.get("", {}) or {}
    root_name = root_entry.get("name") or data.get("name") or "unknown"
    root_version = str(root_entry.get("version") or data.get("version") or "0.0.0")
    packages = [
        DependencyNode(
            name=root_name, version=root_version, ecosystem="npm", is_root=True
        )
    ]
    edges: List[DependencyEdge] = []

    name_to_node: Dict[str, DependencyNode] = {}
    for key, entry in all_entries.items():
        if key == "" or not isinstance(entry, dict):
            continue
        # 取最后一段 node_modules/ 之后的包名（嵌套 node_modules/a/node_modules/b → b）
        name = key.rsplit("node_modules/", 1)[-1]
        if not name or not entry.get("version"):
            continue
        node = DependencyNode(
            name=name,
            version=str(entry["version"]),
            ecosystem="npm",
            version_resolved=True,
        )
        if name in name_to_node:
            continue  # 同名嵌套：首见为准（PK 语义），不重复建节点
        name_to_node[name] = node
        packages.append(node)

    # 根约束边（dependencies + devDependencies 分组信息供规则引擎使用）
    for group in ("dependencies", "devDependencies"):
        for dep_name, constraint in (root_entry.get(group) or {}).items():
            edges.append(
                DependencyEdge(
                    source=root_name,
                    target=dep_name,
                    constraint=str(constraint),
                    properties={"group": group},
                )
            )

    # lockfile 内部依赖边（目标未锁定时跳过并计数，不打断整批）
    inner_skipped = 0
    for key, entry in all_entries.items():
        if key == "" or not isinstance(entry, dict):
            continue
        src_name = key.rsplit("node_modules/", 1)[-1]
        for dep_name, constraint in (entry.get("dependencies") or {}).items():
            if dep_name in name_to_node:
                edges.append(
                    DependencyEdge(
                        source=src_name,
                        target=dep_name,
                        constraint=str(constraint),
                    )
                )
            else:
                inner_skipped += 1
    if inner_skipped:
        logger.info(f"package-lock 内部边跳过 {inner_skipped} 条（目标未出现在锁定清单）")

    return packages, edges


def parse_poetry_lock(project_path: str):
    """poetry.lock：[[package]] 精确版本；图约束边来自同目录 pyproject.toml。"""
    path_obj = Path(project_path)
    try:
        import tomllib
    except ImportError:
        import tomli as tomllib  # type: ignore
    try:
        with path_obj.open("rb") as f:
            data = tomllib.load(f)
    except Exception as e:
        logger.error(f"解析 TOML 文件失败: {e}")
        sys.exit(EXIT_INPUT_ERROR)

    root_info = _lockfile_root_from_toml(path_obj, "pyproject.toml")
    root_name = root_info.get("name", "unknown")
    packages = [
        DependencyNode(
            name=root_name,
            version=root_info.get("version", "0.0.0"),
            ecosystem="pypi",
            is_root=True,
        )
    ]

    constraints = _manifest_constraints(path_obj, "pyproject.toml")
    edges: List[DependencyEdge] = []
    seen: set = set()
    for pkg in data.get("package", []) or []:
        if not isinstance(pkg, dict) or not pkg.get("name") or not pkg.get("version"):
            continue
        name = str(pkg["name"]).lower()
        if name in seen:
            continue
        seen.add(name)
        packages.append(
            DependencyNode(
                name=name,
                version=str(pkg["version"]),
                ecosystem="pypi",
                version_resolved=True,
            )
        )
        if name in constraints:
            edges.append(
                DependencyEdge(
                    source=root_name, target=name, constraint=constraints[name]
                )
            )
    return packages, edges


def parse_cargo_lock(project_path: str):
    """Cargo.lock：[[package]] name/version + dependencies 数组（含 "name ver" 消歧）。"""
    path_obj = Path(project_path)
    try:
        import tomllib
    except ImportError:
        import tomli as tomllib  # type: ignore
    try:
        with path_obj.open("rb") as f:
            data = tomllib.load(f)
    except Exception as e:
        logger.error(f"解析 TOML 文件失败: {e}")
        sys.exit(EXIT_INPUT_ERROR)

    root_info = _lockfile_root_from_toml(path_obj, "Cargo.toml")
    root_name = root_info.get("name", "unknown")
    packages = [
        DependencyNode(
            name=root_name,
            version=root_info.get("version", "0.0.0"),
            ecosystem="crates",
            is_root=True,
        )
    ]
    edges: List[DependencyEdge] = []

    # 根约束边来自 Cargo.toml [dependencies]（缺 manifest 时退化为无根边）
    root_constraints: Dict[str, str] = {}
    manifest = path_obj.parent / "Cargo.toml"
    if manifest.is_file():
        try:
            import tomllib as _tomllib
        except ImportError:
            import tomli as _tomllib  # type: ignore
        try:
            with manifest.open("rb") as f:
                cargo_toml = _tomllib.load(f)
            for dep_name, spec in (cargo_toml.get("dependencies") or {}).items():
                if isinstance(spec, dict):
                    ver = spec.get("version")
                    root_constraints[dep_name] = str(ver) if ver else "*"
                else:
                    root_constraints[dep_name] = str(spec) if spec else "*"
        except Exception as e:
            logger.warning(f"解析 Cargo.toml 依赖约束失败（跳过根约束边）: {e}")

    name_to_node: Dict[str, DependencyNode] = {}
    for pkg in data.get("package", []) or []:
        if not isinstance(pkg, dict) or not pkg.get("name") or not pkg.get("version"):
            continue
        name = str(pkg["name"])
        if name in name_to_node:
            continue
        node = DependencyNode(
            name=name,
            version=str(pkg["version"]),
            ecosystem="crates",
            version_resolved=True,
        )
        name_to_node[name] = node
        packages.append(node)
        if name in root_constraints:
            edges.append(
                DependencyEdge(
                    source=root_name,
                    target=name,
                    constraint=root_constraints[name],
                )
            )

    # 内部依赖边："cfg-if 1.0.0"（同名多版本消歧）或 "getrandom"
    for pkg in data.get("package", []) or []:
        if not isinstance(pkg, dict):
            continue
        src_name = str(pkg.get("name", ""))
        for dep_label in pkg.get("dependencies", []) or []:
            dep_name, dep_ver = _name_version(str(dep_label))
            target = name_to_node.get(dep_name)
            if target is None:
                continue
            if dep_ver and target.version != dep_ver:
                continue  # 多版本场景：指向的不是当前节点，跳过（显性近似）
            edges.append(
                DependencyEdge(source=src_name, target=dep_name, constraint="*")
            )
    return packages, edges


def parse_composer_lock(project_path: str):
    """composer.lock：packages + packages-dev 精确版本；根约束来自 composer.json。"""
    path_obj = Path(project_path)
    try:
        with path_obj.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        logger.error(f"解析 JSON 文件失败: {e}")
        sys.exit(EXIT_INPUT_ERROR)

    root_name = "unknown"
    root_constraints: Dict[str, str] = {}
    manifest = path_obj.parent / "composer.json"
    if manifest.is_file():
        try:
            with manifest.open("r", encoding="utf-8") as f:
                composer = json.load(f)
            # 保留完整 vendor/name 作为根名（与包节点命名空间一致，避免同名歧义）
            root_name = composer.get("name") or "unknown"
            root_constraints = dict(composer.get("require") or {})
        except Exception as e:
            logger.warning(f"解析 composer.json 失败（根节点信息降级）: {e}")

    packages = [
        DependencyNode(
            name=root_name,
            version="0.0.0",
            ecosystem="packagist",
            is_root=True,
        )
    ]
    edges: List[DependencyEdge] = []

    def _is_platform_dep(name: str) -> bool:
        return name == "php" or name.startswith("ext-") or name.startswith("lib-")

    for group, group_key in (("dependencies", "packages"), ("dev", "packages-dev")):
        for pkg in data.get(group_key, []) or []:
            if not isinstance(pkg, dict) or not pkg.get("name"):
                continue
            full_name = str(pkg["name"])
            node = DependencyNode(
                name=full_name,
                version=str(pkg.get("version", "")),
                ecosystem="packagist",
                version_resolved=True,
                properties={"group": group},
            )
            packages.append(node)
            if full_name in root_constraints and group == "dependencies":
                edges.append(
                    DependencyEdge(
                        source=root_name,
                        target=full_name,
                        constraint=str(root_constraints[full_name]),
                    )
                )

    name_set = {p.name for p in packages}
    for group_key in ("packages", "packages-dev"):
        for pkg in data.get(group_key, []) or []:
            if not isinstance(pkg, dict) or not pkg.get("name"):
                continue
            for dep_name, constraint in (pkg.get("require") or {}).items():
                if _is_platform_dep(str(dep_name)) or str(dep_name) not in name_set:
                    continue
                edges.append(
                    DependencyEdge(
                        source=str(pkg["name"]),
                        target=str(dep_name),
                        constraint=str(constraint),
                    )
                )
    return packages, edges


def parse_gemfile_lock(project_path: str):
    """Gemfile.lock：GEM specs 精确版本 + DEPENDENCIES 根约束（文本格式逐行解析）。"""
    path_obj = Path(project_path)
    try:
        lines = path_obj.read_text(encoding="utf-8", errors="replace").splitlines()
    except Exception as e:
        logger.error(f"读取文件失败: {e}")
        sys.exit(EXIT_INPUT_ERROR)

    root_name = path_obj.parent.name or "unknown"
    packages = [
        DependencyNode(
            name=root_name, version="0.0.0", ecosystem="rubygems", is_root=True
        )
    ]
    edges: List[DependencyEdge] = []
    name_to_node: Dict[str, DependencyNode] = {}

    section = ""
    in_specs = False
    current_spec: Optional[str] = None
    # specs 按字母序排列，依赖约束行可能先于目标 spec 行出现——先收集后建边
    pending_inner: List[tuple] = []  # (source, target, constraint)
    for line in lines:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line.startswith(" "):
            section = line.strip()
            in_specs = False
            current_spec = None
            continue
        stripped = line.strip()
        if section == "GEM":
            if stripped == "specs:":
                in_specs = True
                current_spec = None
                continue
            if not in_specs:
                continue  # remote: 等 GEM 段元数据行
            m = re.match(r"^([^\s(]+)(?: \(([^)]+)\))?$", stripped)
            if not m:
                continue
            name, version = m.group(1), m.group(2)
            indent = len(line) - len(line.lstrip(" "))
            if indent <= 4:
                # 4 空格缩进 = 锁定包行
                if version and name not in name_to_node:
                    node = DependencyNode(
                        name=name,
                        version=version,
                        ecosystem="rubygems",
                        version_resolved=True,
                    )
                    name_to_node[name] = node
                    packages.append(node)
                current_spec = name if name in name_to_node else None
            elif current_spec is not None:
                # 6+ 空格缩进 = 上一锁定包的传递依赖约束行
                pending_inner.append((current_spec, name, version or "*"))
        elif section == "DEPENDENCIES":
            m = re.match(r"^([^\s(]+)(?: \(([^)]+)\))?$", stripped)
            if m and m.group(1) in name_to_node:
                edges.append(
                    DependencyEdge(
                        source=root_name,
                        target=m.group(1),
                        constraint=m.group(2) or "*",
                    )
                )

    skipped_inner = 0
    for src, target, constraint in pending_inner:
        if target in name_to_node:
            edges.append(
                DependencyEdge(source=src, target=target, constraint=constraint)
            )
        else:
            skipped_inner += 1
    if skipped_inner:
        logger.info(
            f"Gemfile.lock 内部边跳过 {skipped_inner} 条（目标未出现在锁定 specs 清单）"
        )
    return packages, edges


# parser 逻辑名 → 实现函数（文件清单与生态归属的单一来源在 ecosystem_registry，
# 新增可解析文件 = 注册表加一条目 + 此处加一个函数引用）
PARSER_FUNCS = {
    "pyproject": parse_pyproject_toml,
    "requirements": parse_requirements_txt,
    "package_json": parse_package_json,
    "package_lock": parse_package_lock_json,
    "poetry_lock": parse_poetry_lock,
    "cargo_lock": parse_cargo_lock,
    "composer_lock": parse_composer_lock,
    "gemfile_lock": parse_gemfile_lock,
}


def cmd_analyze_data(args):
    """分析依赖数据文件"""
    data_file = args.data_file
    data_path = Path(data_file)

    if not data_path.exists():
        logger.error(f"找不到文件 {data_file}")
        sys.exit(EXIT_INPUT_ERROR)

    # 读取 JSON 数据
    try:
        with data_path.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        logger.error(f"解析 JSON 文件失败: {e}")
        sys.exit(EXIT_INPUT_ERROR)

    # 验证数据格式
    if "packages" not in data or "edges" not in data:
        logger.error("JSON 文件必须包含 'packages' 和 'edges' 字段")
        sys.exit(EXIT_INPUT_ERROR)

    logger.info(f"正在分析依赖数据: {data_file}")

    # 解析数据（version 归一化见 _deps_data_to_graph）
    packages, edges = _deps_data_to_graph(data)

    logger.info(f"加载 {len(packages)} 个包, {len(edges)} 个依赖关系")

    # 创建分析器
    analyzer = DependencyAnalyzer()
    analyzer.exemptions = load_exemptions_for(args, data, data_path)

    # --exit-code 契约：任一执行分支发现的漏洞都计入退出判定
    found_vulns: List[SecurityVulnerability] = []

    try:
        # 构建依赖图
        analyzer.build_dependency_graph(packages, edges)

        # 执行分析
        if args.conflicts:
            conflicts = analyzer.detect_conflicts()
            display_conflicts(conflicts)

        if args.recommend:
            recommendations = analyzer.recommend_optimal_versions()
            display_recommendations(recommendations)

        if args.security:
            vulns = analyzer.assess_security()
            display_vulnerabilities(vulns)
            display_ignored_vulnerabilities(analyzer.ignored_vulnerabilities)
            found_vulns = vulns

        if args.updates:
            update_paths = analyzer.plan_update_paths()
            display_update_paths(update_paths)

        # 生成完整报告
        if args.report:
            root_pkg = packages[0].name if packages else "unknown"
            report = analyzer.generate_report(root_pkg)
            found_vulns = report.vulnerabilities

            output_file = args.output if args.output else "dependency_report.json"
            analyzer.export_report_json(report, output_file)
            display_ignored_vulnerabilities(report.ignored_vulnerabilities)
            logger.info(f"报告已保存到: {output_file}")

        # 显示摘要
        if not any(
            [args.conflicts, args.recommend, args.security, args.updates, args.report]
        ):
            # 默认显示所有分析
            conflicts = analyzer.detect_conflicts()
            recommendations = analyzer.recommend_optimal_versions()
            vulns = analyzer.assess_security()
            found_vulns = vulns
            update_paths = analyzer.plan_update_paths()

            logger.info("分析摘要")
            logger.info(f"总包数: {len(packages)}")
            logger.info(f"总依赖关系: {len(edges)}")
            logger.info(f"冲突数: {len(conflicts)}")
            logger.info(f"安全漏洞: {len(vulns)}")
            logger.info(f"更新建议: {len(update_paths)}")
            display_ignored_vulnerabilities(analyzer.ignored_vulnerabilities)

            if conflicts:
                logger.warning(f"发现 {len(conflicts)} 个依赖冲突")
            if vulns:
                logger.warning(f"发现 {len(vulns)} 个安全漏洞")
            if update_paths:
                logger.info(f"有 {len(update_paths)} 个包可以更新")

            if not conflicts and not vulns and not update_paths:
                logger.info("依赖状态良好")

    finally:
        try:
            analyzer.close()
        except Exception as e:
            logger.error(f"关闭分析器时出错: {e}")

    # CI 门禁退出码：发现漏洞即按 --exit-code 指定的码退出（默认 0 不影响既有调用）
    exit_code = getattr(args, "exit_code", 0) or 0
    if exit_code and found_vulns:
        logger.info(
            f"--exit-code {exit_code}：发现 {len(found_vulns)} 个漏洞，按契约退出 {exit_code}"
        )
        sys.exit(exit_code)


def enrich_licenses(
    packages: List[DependencyNode],
    fetcher: Optional[Any] = None,
    db: Optional["DependencyGraphDB"] = None,
) -> List[Dict[str, str]]:
    """批量查询 registry 采集依赖包 license，并回写图 DB（G1/G2 共用单一数据源）。

    数据流（license 的单一存储点是图 DB 的 Package.license）：
    - 只处理非根包（根包是项目自身，不属于依赖许可证合规范围）
    - 查询结果经 db.set_license 回写 Package.license（DB 成为真正的存储点）；
      同步写 node.properties["license"] 作为同进程纯函数（_to_deps_data /
      SBOM）的传递载体；未获取到时为空串（数据层"无数据"语义，SBOM 端
      回退 SPDX 标准的 NOASSERTION）
    - 报告层（_collect_license_info）从 DB 读回，空串以 "UNKNOWN" 显式标注
      （供健康度评分按未知风险计分）

    性能注：批量协议为 EcosystemFetcher.fetch_many → 每个生态系统一次
    `--batch` 子进程（内部 4 线程并发查 registry）。100 依赖此前需 ~100 个
    Python 子进程（4 并发下 ≈ 40s，主要为解释器/导入启动开销），现降为
    每生态 1 个子进程。fetch_many 整体异常时全员标 UNKNOWN——不回退逐包
    串行 fetch（网络故障下 100 包 × 最坏 15s ≈ 25 分钟）。

    Args:
        packages: 依赖节点列表
        fetcher: 可选 license 查询器（需有 fetch(name, ecosystem) -> dict，
                 可选 fetch_many(items) -> {(name, eco): dict}，批量优先）；
                 None 时构造 readme_generator.EcosystemFetcher（subprocess
                 调 ecosystem 脚本）。测试注入 mock 避免联网。
        db: 可选图 DB；提供时查询结果回写 Package.license（单一存储点）

    Returns:
        license_info 列表（与非根包等长同序）：
        [{"package": name, "license": "MIT" | "UNKNOWN"}, ...]
    """
    dep_packages = [p for p in packages if not p.is_root]
    if not dep_packages:
        return []

    if fetcher is None:
        import readme_generator

        fetcher = readme_generator.EcosystemFetcher()

    use_batch = hasattr(fetcher, "fetch_many")
    batch_failed = False
    infos: Dict[Tuple[str, str], dict] = {}
    if use_batch:
        try:
            infos = fetcher.fetch_many([(p.name, p.ecosystem) for p in dep_packages])
        except Exception as e:
            # 不回退逐包串行 fetch：网络故障下逐包重试最坏 O(n)×15s，
            # 全员标 UNKNOWN（数据层空串 → 报告层 UNKNOWN 语义现成）
            logger.warning(f"fetch_many 批量查询 license 失败，全员标 UNKNOWN: {e}")
            batch_failed = True

    license_info: List[Dict[str, str]] = []
    for pkg in dep_packages:
        info: dict = {}
        if batch_failed:
            pass  # 批量失败：该包显式 UNKNOWN，不做逐包串行重试
        elif use_batch:
            info = infos.get((pkg.name, pkg.ecosystem), {})
        else:
            # fetcher 无批量能力（如测试 mock）时的逐个查询路径
            try:
                info = fetcher.fetch(pkg.name, pkg.ecosystem) or {}
            except Exception as e:
                logger.debug(f"查询 {pkg.ecosystem}/{pkg.name} license 失败: {e}")
                info = {}
        license_str = (info or {}).get("license", "") or ""
        # 数据层保持"无数据=空串"语义；报告层以 UNKNOWN 显式标注，禁止静默
        pkg.properties["license"] = license_str
        if db is not None:
            db.set_license(pkg.name, license_str)
        license_info.append(
            {"package": pkg.name, "license": license_str or "UNKNOWN"}
        )
    return license_info


def _to_deps_data(packages: List[DependencyNode], edges: List[DependencyEdge]) -> dict:
    """
    将 DependencyNode/Edge 列表转为 deps_data dict schema

    用于 visualizer / readme_generator / impact_analyzer / sbom_generator 等模块的输入
    （与 cmd_report 输入的 deps_data.json schema 一致）

    license 取自 node.properties["license"]（enrich_licenses 的写入结果，
    单一存储点是图 DB Package.license——cmd_readme 等调用方在 enrich 后
    从 DB 读回覆盖此键）；未采集时为空串，SBOM 端以 NOASSERTION 显式标注
    """
    return {
        "packages": [
            {
                "name": p.name,
                "version": p.version,
                "ecosystem": p.ecosystem,
                "is_root": p.is_root,
                "license": p.properties.get("license", ""),
                "version_resolved": p.version_resolved,
            }
            for p in packages
        ],
        "edges": [
            {
                "source": e.source,
                "target": e.target,
                "constraint": e.constraint,
            }
            for e in edges
        ],
    }


def cmd_list_parsers() -> None:
    """打印各生态解析能力自省表（--list-parsers，来自 ecosystem_registry）。"""
    print(f"{'生态':<12}{'状态':<18}{'manifest 解析':<34}lockfile 解析")
    for row in eco_reg.parser_status():

        def fmt(entries: List[Dict[str, Any]]) -> str:
            parts = []
            for e in entries:
                parts.append(
                    f"{e['file']}:{e['parser'] or '未实现'}"
                )
            return ", ".join(parts)

        print(
            f"{row['ecosystem']:<12}{row['status']:<18}{fmt(row['manifests']):<34}{fmt(row['lockfiles'])}"
        )


def cmd_analyze(args):
    """分析项目依赖"""
    if getattr(args, "list_parsers", False):
        cmd_list_parsers()
        return

    project_path = args.project
    if not project_path:
        logger.error("analyze 需要项目路径或依赖文件路径（--list-parsers 可省略）")
        sys.exit(1)

    logger.info(f"正在分析项目: {project_path}")

    # 智能解析项目依赖
    packages, edges, ecosystem = parse_dependencies(project_path)

    logger.info(f"找到 {len(packages)} 个包, {len(edges)} 个依赖关系")

    # 创建分析器
    analyzer = DependencyAnalyzer()

    try:
        # 构建依赖图
        analyzer.build_dependency_graph(packages, edges)

        # 可视化依赖树（Mermaid flowchart）
        if getattr(args, "visualize", False):
            import visualizer

            deps_data = _to_deps_data(packages, edges)
            depth = getattr(args, "depth", 3) or 3
            mermaid = visualizer.render_mermaid_tree(deps_data, depth=depth)
            output_file = getattr(args, "output", None)
            if output_file:
                out_path = Path(output_file)
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_path.write_text(mermaid, encoding="utf-8")
                logger.info(f"依赖树已写入: {output_file}")
            else:
                print(mermaid)

        # 冲突影响范围分析
        if getattr(args, "impact", False):
            import impact_analyzer

            deps_data = _to_deps_data(packages, edges)
            conflicts = analyzer.detect_conflicts()
            conflicts_data = [
                {
                    "package": c.package,
                    "required_by": c.required_by,
                    "conflict_type": c.conflict_type,
                    "severity": c.severity.value,
                    "suggestion": c.suggestion,
                }
                for c in conflicts
            ]
            impacts = impact_analyzer.analyze_conflict_impact(deps_data, conflicts_data)
            output_file = getattr(args, "output", None)
            if output_file:
                out_path = Path(output_file)
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_path.write_text(
                    json.dumps(impacts, indent=2, ensure_ascii=False),
                    encoding="utf-8",
                )
                logger.info(f"影响分析已写入: {output_file}")
            else:
                print(impact_analyzer.format_impact_report(impacts))

        # 执行分析
        if args.conflicts:
            conflicts = analyzer.detect_conflicts()
            display_conflicts(conflicts)

        if args.recommend:
            recommendations = analyzer.recommend_optimal_versions()
            display_recommendations(recommendations)

        if args.security:
            vulns = analyzer.assess_security()
            display_vulnerabilities(vulns)

        if args.updates:
            update_paths = analyzer.plan_update_paths()
            display_update_paths(update_paths)

        # 生成完整报告
        if args.report:
            report = analyzer.generate_report(packages[0].name)

            output_file = args.output if args.output else "dependency_report.json"
            analyzer.export_report_json(report, output_file)
            logger.info(f"报告已保存到: {output_file}")

        # 显示摘要
        if not any(
            [
                args.conflicts,
                args.recommend,
                args.security,
                args.updates,
                args.report,
                getattr(args, "visualize", False),
                getattr(args, "impact", False),
            ]
        ):
            # 默认显示所有分析
            conflicts = analyzer.detect_conflicts()
            recommendations = analyzer.recommend_optimal_versions()
            vulns = analyzer.assess_security()
            update_paths = analyzer.plan_update_paths()

            logger.info("分析摘要")
            logger.info(f"总包数: {len(packages)}")
            logger.info(f"总依赖关系: {len(edges)}")
            logger.info(f"冲突数: {len(conflicts)}")
            logger.info(f"安全漏洞: {len(vulns)}")
            logger.info(f"更新建议: {len(update_paths)}")

            if conflicts:
                logger.warning(f"发现 {len(conflicts)} 个依赖冲突")
            if vulns:
                logger.warning(f"发现 {len(vulns)} 个安全漏洞")
            if update_paths:
                logger.info(f"有 {len(update_paths)} 个包可以更新")

            if not conflicts and not vulns and not update_paths:
                logger.info("依赖状态良好")

    finally:
        try:
            analyzer.close()
        except Exception as e:
            logger.error(f"关闭分析器时出错: {e}")


def cmd_query(args):
    """查询包信息"""
    package_name = args.package
    ecosystem = args.ecosystem or "pypi"

    logger.info(f"正在查询 {ecosystem} 包: {package_name}")

    # 生态 → 子脚本入口来自单一注册表
    script_name = eco_reg.script_for(ecosystem)
    if not script_name:
        logger.error(f"不支持的生态系统 {ecosystem}")
        sys.exit(1)

    # 执行查询
    script_path = Path(__file__).parent / script_name

    import subprocess

    result = subprocess.run(
        [sys.executable, str(script_path), package_name], capture_output=True, text=True
    )

    if result.returncode == 0:
        print(result.stdout)
    else:
        logger.error(f"错误: {result.stderr}")
        sys.exit(1)


def cmd_search(args):
    """搜索包"""
    keyword = args.keyword
    ecosystem = args.ecosystem or "pypi"

    logger.info(f"正在 {ecosystem} 中搜索: {keyword}")

    # 生态 → 子脚本入口来自单一注册表
    script_name = eco_reg.script_for(ecosystem)
    if not script_name:
        logger.error(f"不支持的生态系统 {ecosystem}")
        sys.exit(1)

    script_path = Path(__file__).parent / script_name

    import subprocess

    result = subprocess.run(
        [sys.executable, str(script_path), "--search", keyword],
        capture_output=True,
        text=True,
    )

    if result.returncode == 0:
        print(result.stdout)
    else:
        logger.error(f"错误: {result.stderr}")
        sys.exit(1)


def _security_deps_data(
    package_name: str, version: str, ecosystem: str
) -> Dict[str, Any]:
    """构造 security 子命令的 deps_data（被检包视为根依赖，ecosystem 随 -e 参数）。"""
    return {
        "packages": [
            {
                "name": package_name,
                "version": version,
                "is_root": True,
                "ecosystem": ecosystem,
            }
        ],
        "edges": [],
    }


def cmd_security(args):
    """检查安全漏洞"""
    package_name = args.package
    ecosystem = getattr(args, "ecosystem", "pypi")

    print(f"正在检查包安全漏洞: {package_name} (ecosystem: {ecosystem})")
    print("=" * 70)

    # 查询包真实最新版本（避免用假版本导致 false positive）
    latest_version = None
    try:
        import json as _json
        import subprocess as _sp

        script_name = eco_reg.script_for(ecosystem)
        if not script_name:
            print(f"\n❌ 不支持 ecosystem={ecosystem}（注册表无对应查询脚本）")
            return
        script_path = Path(__file__).parent / script_name
        if not script_path.exists():
            print(f"\n❌ 不支持 ecosystem={ecosystem}（找不到 {script_path.name}）")
            return
        result = _sp.run(
            [sys.executable, str(script_path), package_name],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode == 0:
            pkg_info = _json.loads(result.stdout)
            latest_version = pkg_info.get("latest_version", "")
    except Exception as e:
        logger.warning(f"查询 {package_name} 最新版本失败: {e}")

    if not latest_version:
        print(f"\n⚠️ 无法获取 {package_name} 的最新版本（网络不可用或包不存在）")
        print("   跳过漏洞检查：使用假版本会导致 false positive 报告。")
        print("   请检查网络连接或确认包名后重试。")
        return

    print(f"最新版本: {latest_version}")

    # 创建临时分析器
    analyzer = DependencyAnalyzer()

    # 豁免清单（R7）：--config 显式或进程工作目录 .dayv.toml 自动探测
    import exemptions as exemptions_mod

    config = getattr(args, "config", None)
    if config:
        analyzer.exemptions = exemptions_mod.load_exemptions(config)
    else:
        auto = exemptions_mod.find_config_file(Path.cwd())
        if auto:
            logger.info(f"自动加载豁免配置: {auto}")
            analyzer.exemptions = exemptions_mod.load_exemptions(str(auto))

    try:
        # 用真实版本创建 DependencyNode
        pkg = DependencyNode(
            name=package_name, version=latest_version, ecosystem=ecosystem
        )

        packages = [pkg]
        edges = []

        analyzer.build_dependency_graph(packages, edges)

        # OSV 扫描失败时显式告知（不静默谎报"无漏洞"）
        if not analyzer.osv_scan_status.get("scanned"):
            print(
                f"\n⚠️ 安全漏洞扫描未完成：{analyzer.osv_scan_status.get('reason', '未知')}"
            )
            print("   漏洞列表可能不完整，请检查网络后重试或人工核查。")
            return

        # 检查漏洞
        vulns = analyzer.assess_security()

        if vulns:
            # --priority: 按 CVSS + exploit + business 加权排序
            if getattr(args, "priority", False):
                import vulnerability_prioritizer

                vuln_dicts = [
                    {
                        "cve_id": v.cve_id,
                        "package": v.package,
                        "version": v.version,
                        "severity": v.severity.value,
                        "description": v.description,
                        "fixed_version": v.fixed_version,
                        "cvss_vector": v.cvss_vector,
                        "cvss_score": v.cvss_score,
                    }
                    for v in vulns
                ]
                # 单包 security 查询：被检查的包本身视为根依赖（ecosystem 随 -e）
                deps_data = _security_deps_data(package_name, latest_version, ecosystem)
                prioritized = vulnerability_prioritizer.prioritize_vulnerabilities(
                    vuln_dicts, deps_data
                )
                print(f"\n发现 {len(vulns)} 个安全漏洞（按修复优先级排序）:")
                print(vulnerability_prioritizer.format_priority_report(prioritized))
            else:
                print(f"\n发现 {len(vulns)} 个安全漏洞:")
                for vuln in vulns:
                    print(f"\n  CVE: {vuln.cve_id}")
                    print(f"  包: {vuln.package}")
                    print(f"  影响版本: {vuln.version}")
                    print(f"  严重级别: {vuln.severity.value}")
                    print(f"  描述: {vuln.description}")
                    if vuln.fixed_version:
                        print(f"  修复版本: {vuln.fixed_version}")
        else:
            print("\n✅ 未发现已知安全漏洞")

        display_ignored_vulnerabilities(analyzer.ignored_vulnerabilities)

        # CI 门禁退出码：发现漏洞即按 --exit-code 指定的码退出（默认 0 兼容）
        exit_code = getattr(args, "exit_code", 0) or 0
        if exit_code and vulns:
            print(f"\n--exit-code {exit_code}：发现 {len(vulns)} 个漏洞，按契约退出")
            sys.exit(exit_code)

    finally:
        analyzer.close()


def cmd_report(args):
    """生成完整报告（支持 json/html/pdf/sbom 格式）"""
    data_file = args.data_file
    fmt = getattr(args, "format", "json") or "json"
    output_file = args.output  # 默认 None，按格式决定

    print(f"正在生成依赖报告: {data_file} (format={fmt})")
    print("=" * 70)

    data_path = Path(data_file)
    if not data_path.exists():
        logger.error(f"找不到文件 {data_file}")
        sys.exit(EXIT_INPUT_ERROR)

    try:
        with data_path.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        logger.error(f"解析 JSON 文件失败: {e}")
        sys.exit(EXIT_INPUT_ERROR)

    if "packages" not in data or "edges" not in data:
        logger.error("JSON 文件必须包含 'packages' 和 'edges' 字段")
        sys.exit(EXIT_INPUT_ERROR)

    # SBOM 格式：直接用 packages + edges 生成 SPDX（无需分析报告）
    if fmt == "sbom":
        import sbom_generator

        project_name = data["packages"][0]["name"] if data["packages"] else "unknown"
        if output_file is None:
            output_file = f"{project_name}-sbom.spdx.json"
        try:
            result_path = sbom_generator.write_sbom(
                packages=data["packages"],
                edges=data["edges"],
                project_name=project_name,
                output_path=output_file,
            )
            print(f"SBOM 已生成: {result_path}")
        except Exception as e:
            logger.error(f"SBOM 生成失败: {e}")
            sys.exit(1)
        return

    # JSON/HTML/PDF：先生成分析报告
    # （version 归一化见 _deps_data_to_graph：伪版本/范围串不得原样送 OSV）
    packages, edges = _deps_data_to_graph(data)

    analyzer = DependencyAnalyzer()
    try:
        analyzer.build_dependency_graph(packages, edges)
        report = analyzer.generate_report(packages[0].name if packages else "unknown")
        report_dict = analyzer.report_to_dict(report)
    finally:
        analyzer.close()

    # 默认输出文件名
    if output_file is None:
        output_file = "dependency_report.json"

    # 按格式分派到 report_renderer
    import report_renderer

    try:
        result_path = report_renderer.render_report(report_dict, output_file, fmt=fmt)
        print(f"报告已生成: {result_path} (format={fmt})")
    except ValueError as e:
        logger.error(str(e))
        sys.exit(1)
    except RuntimeError as e:
        # weasyprint 不可用等运行时错误
        logger.error(str(e))
        sys.exit(1)


def cmd_health(args):
    """依赖健康度评分（5 维度 + 雷达图 + 改进建议）"""
    project_path = args.project

    print(f"正在评估依赖健康度: {project_path}")
    print("=" * 70)

    # 解析依赖（与 cmd_analyze 一致）
    packages, edges, ecosystem = parse_dependencies(project_path)
    print(f"找到 {len(packages)} 个包, {len(edges)} 个依赖关系 (ecosystem={ecosystem})")

    analyzer = DependencyAnalyzer()
    try:
        analyzer.build_dependency_graph(packages, edges)
        report = analyzer.generate_report(packages[0].name if packages else "unknown")
        report_dict = analyzer.report_to_dict(report)
    finally:
        analyzer.close()

    # 计算健康度评分
    import health_scorer

    result = health_scorer.score_health(report_dict)

    # 输出结果
    print()
    print(f"  总分: {result['total_score']}/100  等级: {result['level'].upper()}")
    print()
    print("  5 维度评分:")
    dim_names = {
        "version_freshness": "版本新旧度",
        "vulnerability_status": "漏洞状态",
        "maintenance_status": "维护状态",
        "dependency_stability": "依赖稳定性",
        "license_compliance": "许可证合规性",
    }
    for name, score in result["dimensions"].items():
        cn = dim_names.get(name, name)
        bar = "█" * int(score / 5) + "░" * (20 - int(score / 5))
        print(f"    {cn:<12} {bar} {score:>5.1f}")

    print()
    if result["suggestions"]:
        print("  改进建议:")
        for i, s in enumerate(result["suggestions"], 1):
            print(f"    {i}. {s}")
    else:
        print("  ✅ 所有维度均健康，无需特别改进")

    # 雷达图（Mermaid）
    print()
    radar = health_scorer.render_radar_mermaid(result)
    print(radar)

    # 可选：写出 JSON 结果
    if getattr(args, "output", None):
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        print(f"\n评分结果已写入: {args.output}")


def cmd_readme(args):
    """生成项目依赖 README 章节（markdown 表格，按 ecosystem 分组）"""
    project_path = args.project

    print(f"正在生成依赖 README: {project_path}")
    print("=" * 70)

    # 解析依赖
    packages, edges, ecosystem = parse_dependencies(project_path)
    print(f"找到 {len(packages)} 个包, {len(edges)} 个依赖关系 (ecosystem={ecosystem})")

    # 用 EcosystemFetcher 查 registry 获取 description/license
    import readme_generator

    fetcher = readme_generator.EcosystemFetcher()

    # license 单一数据源 = 图 DB：建图后 enrich 采集并回写 Package.license，
    # deps_data 的 license 从 DB 读回（不复用临时节点属性传递）
    analyzer = DependencyAnalyzer()
    try:
        analyzer.build_dependency_graph(packages, edges)
        enrich_licenses(packages, fetcher=fetcher, db=analyzer.db)
        deps_data = _to_deps_data(packages, edges)
        license_map = analyzer.db.get_license_map()
    finally:
        try:
            analyzer.close()
        except Exception as e:
            logger.error(f"关闭分析器时出错: {e}")
    for pkg in deps_data["packages"]:
        pkg["license"] = license_map.get(pkg["name"], "")

    markdown = readme_generator.generate_dependency_readme(deps_data, fetcher=fetcher)

    # 输出
    output_file = getattr(args, "output", None)
    if output_file:
        out_path = Path(output_file)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(markdown, encoding="utf-8")
        print(f"依赖 README 已写入: {output_file}")
    else:
        print(markdown)


def cmd_simulate(args):
    """升级影响模拟（dry-run）"""
    package = args.package
    target_version = args.target_version
    project_path = getattr(args, "project", None)

    print(f"正在模拟升级 {package} -> {target_version}")
    print("=" * 70)

    # 构建 deps_data
    if project_path:
        packages, edges, ecosystem = parse_dependencies(project_path)
        deps_data = _to_deps_data(packages, edges)
    else:
        # 无项目路径：用空 deps_data，仅基于版本号判定风险
        deps_data = {"packages": [], "edges": []}
        ecosystem = "pypi"

    import simulator

    result = simulator.simulate_upgrade(
        deps_data, package, target_version, ecosystem=ecosystem
    )

    output_file = getattr(args, "output", None)
    if output_file:
        out_path = Path(output_file)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        print(f"模拟结果已写入: {output_file}")
    else:
        print(simulator.format_simulation_report(result))


def cmd_monitor(args):
    """漏洞持续监控"""
    project_path = args.project
    cron_schedule = getattr(args, "cron", None)
    webhook_url = getattr(args, "webhook", None)

    import monitor

    # --cron 模式：只生成 crontab 条目，不实际安装
    if cron_schedule:
        entry = monitor.generate_cron_entry(cron_schedule, project_path)
        print("crontab 条目（需手动安装到 crontab -e）：")
        print(entry)
        return

    print(f"正在监控项目: {project_path}")
    print("=" * 70)

    # 执行扫描
    scan_result = monitor.run_scan(project_path)
    ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(scan_result["timestamp"]))
    print(f"扫描时间: {ts}")
    print(f"漏洞总数: {scan_result['total']}")

    # 对比历史
    history_file = monitor.DEFAULT_HISTORY_FILE
    new_vulns = monitor.compare_with_history(scan_result, history_file)

    if new_vulns:
        print(f"\n🚨 检测到 {len(new_vulns)} 个新漏洞:")
        print(monitor.format_alert(new_vulns))

        # webhook 告警
        if webhook_url:
            success = monitor.send_alert(webhook_url, new_vulns)
            if success:
                print(f"\n✅ webhook 告警已发送到 {webhook_url}")
            else:
                print(f"\n❌ webhook 告警发送失败（见日志）")
    else:
        print("\n✅ 无新漏洞")

    # 保存到历史
    monitor.save_scan_to_history(scan_result, history_file)
    print(f"\n扫描结果已保存到历史: {history_file}")


def cmd_optimize(args):
    """优化依赖配置（去重 + 删冗余 + 识别未使用）"""
    project_path = args.project
    print(f"正在优化依赖配置: {project_path}")
    print("=" * 70)

    packages, edges, ecosystem = parse_dependencies(project_path)
    print(f"找到 {len(packages)} 个包, {len(edges)} 个依赖关系 (ecosystem={ecosystem})")
    deps_data = _to_deps_data(packages, edges)

    checks = getattr(args, "check", None)  # None=全部
    # redundant deep 模式（需 fetcher 查 registry）
    fetcher = None
    redundant_enabled = checks is None or "redundant" in checks
    if getattr(args, "deep", False) and redundant_enabled:
        import readme_generator

        fetcher = readme_generator.EcosystemFetcher()

    import dependency_optimizer

    result = dependency_optimizer.optimize(
        project_path, deps_data, ecosystem, checks=checks, fetcher=fetcher
    )

    # quick 模式 fallback 显式告知（不静默成功）
    if (
        "redundant" in result.get("checks_run", [])
        and result.get("redundant_mode") == "quick"
    ):
        print("📝 redundant 为 quick 模式（未用 --deep），结果基于 edges，准确性有限")

    report = dependency_optimizer.format_optimize_report(result)
    output_file = getattr(args, "output", None)
    if output_file:
        import json

        out_path = Path(output_file)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(
            json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        print(f"\n优化结果 JSON 已写入: {output_file}")
        print("\n" + report)
    else:
        print(report)

    # --apply：实际改配置文件（带 backup）。失败显式告知，不静默谎称已应用。
    if getattr(args, "apply", False):
        apply_result = dependency_optimizer.apply_optimization(
            project_path, ecosystem, result, backup=True
        )
        print("\n" + "=" * 70)
        if apply_result.get("applied"):
            removed = apply_result.get("removed", [])
            print(
                f"✅ --apply 已应用：从 {apply_result['file']} 移除 {len(removed)} 个 unused 依赖"
            )
            for name in removed:
                print(f"   - {name}")
            if apply_result.get("backup_path"):
                print(f"📦 备份已写入: {apply_result['backup_path']}")
            if not removed:
                print(f"ℹ️ {apply_result.get('reason', '')}")
        else:
            print(f"⚠️ --apply 未应用：{apply_result.get('reason', '未知原因')}")


def main():
    """主函数 - 命令行入口"""
    parser = argparse.ArgumentParser(
        description="Dependency Analysis Engine - 依赖分析引擎",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  # 分析依赖数据（LLM 提供）
  python dependency_analyzer.py analyze-data deps_data.json
  
  # 只检查冲突
  python dependency_analyzer.py analyze-data deps_data.json --conflicts
  
  # 生成完整报告
  python dependency_analyzer.py analyze-data deps_data.json --report -o report.json
  
  # 查询包信息
  python dependency_analyzer.py query fastapi
  
  # 搜索包
  python dependency_analyzer.py search "web framework"
  
  # 检查安全漏洞
  python dependency_analyzer.py security requests
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="可用命令")

    # analyze-data 命令
    analyze_parser = subparsers.add_parser("analyze-data", help="分析依赖数据文件")
    analyze_parser.add_argument("data_file", help="JSON 格式的依赖数据文件")
    analyze_parser.add_argument("--conflicts", action="store_true", help="只检测冲突")
    analyze_parser.add_argument(
        "--recommend", action="store_true", help="只获取版本推荐"
    )
    analyze_parser.add_argument(
        "--security", action="store_true", help="只检查安全漏洞"
    )
    analyze_parser.add_argument("--updates", action="store_true", help="只显示更新路径")
    analyze_parser.add_argument("--report", action="store_true", help="生成完整报告")
    analyze_parser.add_argument("-o", "--output", help="报告输出文件路径")
    analyze_parser.add_argument(
        "--exit-code",
        type=int,
        default=0,
        metavar="N",
        help="CI 门禁：发现漏洞时以 N 退出（默认 0 保持兼容；输入/解析失败恒为 128）",
    )
    analyze_parser.add_argument(
        "--config",
        default=None,
        help="豁免配置 .dayv.toml 路径（默认自动探测数据文件旁/进程目录）",
    )

    # analyze 命令（保留用于向后兼容）
    analyze_parser2 = subparsers.add_parser("analyze", help="分析项目依赖（旧版）")
    analyze_parser2.add_argument(
        "project",
        nargs="?",
        default=None,
        help="项目路径或 pyproject.toml 路径（--list-parsers 时可省略）",
    )
    analyze_parser2.add_argument("--conflicts", action="store_true", help="只检测冲突")
    analyze_parser2.add_argument(
        "--recommend", action="store_true", help="只获取版本推荐"
    )
    analyze_parser2.add_argument(
        "--security", action="store_true", help="只检查安全漏洞"
    )
    analyze_parser2.add_argument(
        "--updates", action="store_true", help="只显示更新路径"
    )
    analyze_parser2.add_argument("--report", action="store_true", help="生成完整报告")
    analyze_parser2.add_argument(
        "--visualize", action="store_true", help="渲染 Mermaid 依赖树（flowchart TD）"
    )
    analyze_parser2.add_argument(
        "--depth",
        type=int,
        default=3,
        help="依赖树渲染深度（默认 3，从根出发的依赖层数）",
    )
    analyze_parser2.add_argument(
        "--impact",
        action="store_true",
        help="分析冲突影响范围（反向追溯受影响包 + 依赖链）",
    )
    analyze_parser2.add_argument(
        "--list-parsers",
        action="store_true",
        help="列出各生态解析能力自省表（manifest/lockfile parser 实现状态）后退出",
    )
    analyze_parser2.add_argument("-o", "--output", help="报告输出文件路径")

    # query 命令
    query_parser = subparsers.add_parser("query", help="查询包信息")
    query_parser.add_argument("package", help="包名")
    query_parser.add_argument(
        "-e",
        "--ecosystem",
        choices=eco_reg.ecosystem_names(),
        default="pypi",
        help="包生态系统 (默认: pypi)",
    )

    # search 命令
    search_parser = subparsers.add_parser("search", help="搜索包")
    search_parser.add_argument("keyword", help="搜索关键词")
    search_parser.add_argument(
        "-e",
        "--ecosystem",
        choices=eco_reg.ecosystem_names(),
        default="pypi",
        help="包生态系统 (默认: pypi)",
    )

    # security 命令
    security_parser = subparsers.add_parser("security", help="检查安全漏洞")
    security_parser.add_argument("package", help="包名")
    security_parser.add_argument(
        "-e",
        "--ecosystem",
        choices=eco_reg.ecosystem_names(),
        default="pypi",
        help="包生态系统 (默认: pypi)；决定用哪个 registry 查最新版本",
    )
    security_parser.add_argument(
        "--priority",
        action="store_true",
        help="按修复优先级排序（CVSS × 0.5 + exploit × 0.3 + business × 0.2）",
    )
    security_parser.add_argument(
        "--exit-code",
        type=int,
        default=0,
        metavar="N",
        help="CI 门禁：发现漏洞时以 N 退出（默认 0 保持兼容；输入错误恒为 128）",
    )
    security_parser.add_argument(
        "--config",
        default=None,
        help="豁免配置 .dayv.toml 路径（默认自动探测进程工作目录）",
    )

    # report 命令
    report_parser = subparsers.add_parser(
        "report", help="生成完整报告（支持 json/html/pdf/sbom 格式）"
    )
    report_parser.add_argument("data_file", help="JSON 格式的依赖数据文件")
    report_parser.add_argument(
        "-o",
        "--output",
        default=None,
        help="报告输出文件路径 (默认按格式决定: dependency_report.json / {project}-sbom.spdx.json)",
    )
    report_parser.add_argument(
        "--format",
        choices=["json", "html", "pdf", "sbom"],
        default="json",
        help="报告格式 (默认: json)",
    )

    # health 命令
    health_parser = subparsers.add_parser(
        "health", help="依赖健康度评分（5 维度 + 雷达图）"
    )
    health_parser.add_argument("project", help="项目路径或依赖文件路径")
    health_parser.add_argument(
        "-o", "--output", default=None, help="可选: 评分结果 JSON 输出路径"
    )

    # readme 命令
    readme_parser = subparsers.add_parser(
        "readme", help="生成项目依赖 README 章节（markdown）"
    )
    readme_parser.add_argument("project", help="项目路径或依赖文件路径")
    readme_parser.add_argument(
        "-o",
        "--output",
        default=None,
        help="可选: markdown 输出路径（默认输出到 stdout）",
    )

    # simulate 命令
    simulate_parser = subparsers.add_parser("simulate", help="升级影响模拟（dry-run）")
    simulate_parser.add_argument("package", help="待升级的包名")
    simulate_parser.add_argument("target_version", help="目标版本号")
    simulate_parser.add_argument(
        "--project", default=None, help="项目路径（用于分析现有依赖图，可选）"
    )
    simulate_parser.add_argument(
        "-o", "--output", default=None, help="可选: JSON 输出路径（默认输出到 stdout）"
    )

    # monitor 命令
    monitor_parser = subparsers.add_parser("monitor", help="漏洞持续监控")
    monitor_parser.add_argument("project", help="项目路径")
    monitor_parser.add_argument(
        "--cron", default=None, help="生成 crontab 条目（如 '0 9 * * *'），不实际安装"
    )
    monitor_parser.add_argument(
        "--webhook", default=None, help="webhook URL，检测到新漏洞时 POST 告警"
    )

    # optimize 命令
    optimize_parser = subparsers.add_parser(
        "optimize", help="优化依赖配置（去重+删冗余+识别未使用）"
    )
    optimize_parser.add_argument("project", help="项目路径或依赖文件路径")
    optimize_parser.add_argument(
        "--check",
        action="append",
        choices=["dedupe", "redundant", "unused"],
        help="指定检测项（可多次：--check dedupe --check unused，默认全部）",
    )
    optimize_parser.add_argument(
        "--deep",
        action="store_true",
        help="redundant deep 模式（查 registry 准确判断，需网络）",
    )
    optimize_parser.add_argument(
        "--apply",
        action="store_true",
        help="实际改配置文件移除 unused 依赖（自动备份 .dayv.bak；默认仅报告不改文件）",
    )
    optimize_parser.add_argument(
        "-o",
        "--output",
        default=None,
        help="可选: JSON 结果输出路径（默认输出到 stdout）",
    )

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    # 执行对应命令
    commands = {
        "analyze-data": cmd_analyze_data,
        "analyze": cmd_analyze,
        "query": cmd_query,
        "search": cmd_search,
        "security": cmd_security,
        "report": cmd_report,
        "health": cmd_health,
        "readme": cmd_readme,
        "simulate": cmd_simulate,
        "monitor": cmd_monitor,
        "optimize": cmd_optimize,
    }

    commands[args.command](args)


if __name__ == "__main__":
    main()
