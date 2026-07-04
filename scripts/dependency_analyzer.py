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

import real_ladybug as lb

from utils import (
    check_version_constraint,
    compare_versions,
    find_latest_version,
    is_valid_semver,
    sort_versions,
)

# 配置日志
logger = logging.getLogger(__name__)

# 常量定义
MAX_CYCLES_DETECT = 100
MAX_PATHS_FIND = 10
MAX_RECOMMENDATIONS_DISPLAY = 20


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
            self.conn.execute("""
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
            """, {
                "name": package.name,
                "version": package.version,
                "ecosystem": package.ecosystem,
                "is_root": package.is_root,
                "description": package.properties.get("description", ""),
                "license": package.properties.get("license", ""),
                "homepage": package.properties.get("homepage", ""),
                "downloads": downloads
            })
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
            self.conn.execute("""
                MATCH (s:Package {name: $source}), (t:Package {name: $target})
                CREATE (s)-[:DependsOn {
                    constraint: $constraint,
                    edge_type: $edge_type,
                    is_optional: $is_optional
                }]->(t)
            """, {
                "source": edge.source,
                "target": edge.target,
                "constraint": edge.constraint,
                "edge_type": edge.edge_type,
                "is_optional": is_optional
            })
            return True
        except Exception as e:
            logger.error(f"添加依赖失败 {edge.source} -> {edge.target}: {e}")
            return False
    
    def add_conflict(self, pkg1: str, pkg2: str, reason: str, severity: str) -> bool:
        """添加冲突关系"""
        try:
            # 使用参数化查询防止 SQL 注入
            self.conn.execute("""
                MATCH (p1:Package), (p2:Package)
                WHERE p1.name = $pkg1 AND p2.name = $pkg2
                CREATE (p1)-[:ConflictsWith {
                    reason: $reason,
                    severity: $severity
                }]->(p2)
            """, {
                "pkg1": pkg1,
                "pkg2": pkg2,
                "reason": reason,
                "severity": severity
            })
            return True
        except Exception as e:
            logger.error(f"添加冲突失败: {e}")
            return False
    
    def add_vulnerability(self, vuln: SecurityVulnerability) -> bool:
        """添加安全漏洞"""
        try:
            # 使用参数化查询防止 SQL 注入
            self.conn.execute("""
                CREATE (v:Vulnerability {
                    cve_id: $cve_id,
                    package: $package,
                    affected_version: $affected_version,
                    severity: $severity,
                    description: $description,
                    fixed_version: $fixed_version
                })
            """, {
                "cve_id": vuln.cve_id,
                "package": vuln.package,
                "affected_version": vuln.version,
                "severity": vuln.severity.value,
                "description": vuln.description,
                "fixed_version": vuln.fixed_version or ""
            })

            # 无论是否有 fixed_version，都必须建立 Affects 关系
            # 否则 assess_security (MATCH (v)-[:Affects]->(p)) 会漏掉无 fix 的漏洞
            self.conn.execute("""
                MATCH (v:Vulnerability {cve_id: $cve_id}),
                      (p:Package {name: $package})
                CREATE (v)-[:Affects]->(p)
            """, {
                "cve_id": vuln.cve_id,
                "package": vuln.package
            })
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
            result = self.conn.execute("""
                MATCH (p:Package)-[d:DependsOn]->(dep:Package)
                WHERE p.name = $name
                RETURN p.name, p.version, dep.name, dep.version, 
                       d.constraint, d.edge_type
            """, {"name": package_name})
            
            deps = []
            while result.has_next():
                row = result.get_next()
                deps.append({
                    "source": row[0],
                    "source_version": row[1],
                    "target": row[2],
                    "target_version": row[3],
                    "constraint": row[4],
                    "edge_type": row[5],
                })
            return deps
        except Exception as e:
            logger.error(f"查询依赖失败: {e}")
            return []
    
    def query_dependents(self, package_name: str) -> List[Dict[str, Any]]:
        """查询哪些包依赖指定包"""
        try:
            # 使用参数化查询防止 SQL 注入
            result = self.conn.execute("""
                MATCH (p:Package)-[d:DependsOn]->(dep:Package)
                WHERE dep.name = $name
                RETURN p.name, p.version, dep.name, dep.version, d.constraint
            """, {"name": package_name})
            
            dependents = []
            while result.has_next():
                row = result.get_next()
                dependents.append({
                    "source": row[0],
                    "source_version": row[1],
                    "target": row[2],
                    "target_version": row[3],
                    "constraint": row[4],
                })
            return dependents
        except Exception as e:
            logger.error(f"查询依赖者失败: {e}")
            return []
    
    def find_path(self, from_pkg: str, to_pkg: str) -> List[List[str]]:
        """查找两个包之间的依赖路径"""
        try:
            # 使用参数化查询防止 SQL 注入
            result = self.conn.execute("""
                MATCH path = (p1:Package {name: $from})-[:DependsOn*]->(p2:Package {name: $to})
                RETURN path
                LIMIT $limit
            """, {"from": from_pkg, "to": to_pkg, "limit": MAX_PATHS_FIND})
            
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
            result = self.conn.execute("""
                MATCH path = (p:Package)-[:DependsOn*]->(p)
                RETURN path
                LIMIT $limit
            """, {"limit": MAX_CYCLES_DETECT})
            
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
            conflict_count = self.conn.execute("MATCH ()-[:ConflictsWith]->() RETURN COUNT(*)")
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
    
    def __init__(self, db_path: Optional[str] = None):
        """
        初始化分析器
        
        Args:
            db_path: 数据库路径
        """
        self.db = DependencyGraphDB(db_path)
        self.known_vulnerabilities = self._load_vulnerability_db()
    
    def _load_vulnerability_db(self) -> Dict[str, List[SecurityVulnerability]]:
        """加载已知漏洞数据库（示例数据）"""
        # 实际应用中应从安全数据库 API 加载
        return {
            # 示例漏洞数据
            "django": [
                SecurityVulnerability(
                    cve_id="CVE-2023-12345",
                    package="django",
                    version="<4.2.0",
                    severity=SeverityLevel.HIGH,
                    description="SQL injection vulnerability",
                    fixed_version="4.2.0",
                )
            ],
            "requests": [
                SecurityVulnerability(
                    cve_id="CVE-2023-67890",
                    package="requests",
                    version="<2.31.0",
                    severity=SeverityLevel.MEDIUM,
                    description="Information disclosure",
                    fixed_version="2.31.0",
                )
            ]
        }
    
    def build_dependency_graph(self, packages: List[DependencyNode], 
                               dependencies: List[DependencyEdge]) -> bool:
        """
        构建依赖关系图
        
        Args:
            packages: 包节点列表
            dependencies: 依赖边列表
            
        Returns:
            是否成功
        """
        logger.info(f"正在构建依赖图: {len(packages)} 个包, {len(dependencies)} 个依赖关系")
        
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
    
    def _check_and_add_vulnerabilities(self, packages: List[DependencyNode]):
        """检查并添加漏洞信息"""
        for pkg in packages:
            if pkg.name in self.known_vulnerabilities:
                for vuln in self.known_vulnerabilities[pkg.name]:
                    # 检查版本是否受影响
                    if check_version_constraint(pkg.version, vuln.version):
                        self.db.add_vulnerability(vuln)
    
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
                        required_by=[{"package": pkg, "constraint": c} 
                                    for c, pkgs in constraints.items() 
                                    for pkg in pkgs],
                        conflict_type="version_mismatch",
                        severity=SeverityLevel.HIGH,
                        suggestion=f"统一 {pkg_name} 的版本约束"
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
            ver_result = self.db.conn.execute("""
                MATCH (p:Package) WHERE p.name = $name
                RETURN p.version
            """, {"name": target_pkg})
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
    
    def _find_best_compromise(self, versions: List[str], 
                             constraints: List[str]) -> str:
        """找到最佳妥协版本"""
        best_version = versions[0]
        max_satisfied = 0
        
        for version in versions:
            satisfied = sum(1 for c in constraints 
                          if check_version_constraint(version, c))
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
                   v.severity, v.description, v.fixed_version
        """)
        
        vulnerabilities = []
        while result.has_next():
            row = result.get_next()
            vuln = SecurityVulnerability(
                cve_id=row[0],
                package=row[1],
                version=row[2],
                severity=SeverityLevel(row[3]),
                description=row[4],
                fixed_version=row[5] if row[5] else None,
            )
            vulnerabilities.append(vuln)
        
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
                    "reasons": []
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
                    "建议: 在测试环境验证后更新"
                ],
                breaking_changes=[],
                recommendation=f"建议更新到 {info['target']} 以修复安全问题"
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
        
        report = AnalysisReport(
            timestamp=time.time(),
            root_package=root_package,
            total_packages=stats.get("total_packages", 0),
            total_edges=stats.get("total_dependencies", 0),
            conflicts=conflicts,
            vulnerabilities=vulnerabilities,
            update_paths=update_paths,
            recommendations=recommendations_list,
            graph_stats=stats
        )
        
        return report
    
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
        }

    def export_report_json(self, report: AnalysisReport,
                          output_file: str):
        """导出报告为 JSON"""
        report_dict = self.report_to_dict(report)

        output_path = Path(output_file)
        with output_path.open('w', encoding='utf-8') as f:
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
    # 依赖文件映射：文件名 -> 生态系统
    # 注：Go 无中央 registry，按 Non-Goals 排除 go.mod
    dependency_files = {
        "pyproject.toml": "pypi",
        "requirements.txt": "pypi",
        "setup.py": "pypi",
        "package.json": "npm",
        "pom.xml": "maven",
        "build.gradle": "maven",
        "build.gradle.kts": "maven",
        "Cargo.toml": "crates",
        "Gemfile": "rubygems",
        "composer.json": "packagist",
    }

    # 扩展名映射：扩展名 -> 生态系统（用于 .csproj/.fsproj/.vbproj 等）
    dependency_extensions = {
        ".csproj": "nuget",
        ".fsproj": "nuget",
        ".vbproj": "nuget",
    }

    path_obj = Path(project_path)

    # 如果传入的是文件路径
    if path_obj.is_file():
        filename = path_obj.name
        if filename in dependency_files:
            return str(path_obj)
        # 按扩展名匹配（如 MyApp.csproj）
        suffix = path_obj.suffix.lower()
        if suffix in dependency_extensions:
            return str(path_obj)
        logger.warning(f"不支持的依赖文件格式 {filename}")
        return None

    # 如果传入的是目录，扫描查找依赖文件
    if path_obj.is_dir():
        # 先按文件名精确匹配
        for filename, ecosystem in dependency_files.items():
            filepath = path_obj / filename
            if filepath.exists():
                logger.info(f"检测到 {ecosystem} 项目: {filename}")
                return str(filepath)
        # 再按扩展名匹配（.csproj/.fsproj/.vbproj）
        for filepath in path_obj.iterdir():
            if filepath.is_file():
                suffix = filepath.suffix.lower()
                if suffix in dependency_extensions:
                    logger.info(f"检测到 {dependency_extensions[suffix]} 项目: {filepath.name}")
                    return str(filepath)

    return None


def parse_pyproject_toml(project_path: str) -> tuple[List[DependencyNode], List[DependencyEdge]]:
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
            sys.exit(1)
    
    path_obj = Path(project_path)
    if not path_obj.exists():
        logger.error(f"找不到文件 {project_path}")
        sys.exit(1)
    
    # 读取并解析 TOML 文件
    try:
        with path_obj.open('rb') as f:
            data = tomllib.load(f)
    except Exception as e:
        logger.error(f"解析 TOML 文件失败: {e}")
        sys.exit(1)
    
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
            name=project_name,
            version=project_version,
            ecosystem="pypi",
            is_root=True
        )
    ]
    
    edges = []
    
    for dep_str in dependencies:
        # 跳过注释
        if dep_str.startswith('#'):
            continue
        
        # 解析包名和版本约束
        # 格式: package>=1.0.0 或 package==1.0.0 或 package
        # 或者: package[extra]>=1.0.0
        match = re.match(r'([a-zA-Z0-9_-]+)(?:\[.*?\])?\s*(.*)?', dep_str)
        if match:
            pkg_name = match.group(1).lower()
            constraint = match.group(2).strip() if match.group(2) else "*"
            
            # 提取版本号（简化处理）
            ver_match = re.search(r'>=?\s*([0-9][^,\s\]]*)', constraint)
            version = ver_match.group(1) if ver_match else "0.0.0"
            
            packages.append(DependencyNode(
                name=pkg_name,
                version=version,
                ecosystem="pypi"
            ))
            
            edges.append(DependencyEdge(
                source=project_name,
                target=pkg_name,
                constraint=constraint
            ))
    
    return packages, edges


def parse_package_json(project_path: str) -> tuple[List[DependencyNode], List[DependencyEdge]]:
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
        sys.exit(1)
    
    try:
        with path_obj.open('r', encoding='utf-8') as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        logger.error(f"解析 JSON 文件失败: {e}")
        sys.exit(1)
    
    project_name = data.get("name", "unknown")
    project_version = data.get("version", "0.1.0")
    
    packages = [
        DependencyNode(
            name=project_name,
            version=project_version,
            ecosystem="npm",
            is_root=True
        )
    ]
    
    edges = []
    
    # 合并 dependencies 和 devDependencies
    all_deps = {}
    all_deps.update(data.get("dependencies", {}))
    all_deps.update(data.get("devDependencies", {}))
    
    for pkg_name, version_constraint in all_deps.items():
        # 提取版本号
        version = version_constraint.lstrip("^~>=<")
        if not version or not version[0].isdigit():
            version = "0.0.0"
        
        packages.append(DependencyNode(
            name=pkg_name,
            version=version,
            ecosystem="npm"
        ))
        
        edges.append(DependencyEdge(
            source=project_name,
            target=pkg_name,
            constraint=version_constraint
        ))
    
    return packages, edges


def parse_requirements_txt(project_path: str) -> tuple[List[DependencyNode], List[DependencyEdge]]:
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
        sys.exit(1)
    
    try:
        with path_obj.open('r', encoding='utf-8') as f:
            lines = f.readlines()
    except Exception as e:
        logger.error(f"读取文件失败: {e}")
        sys.exit(1)
    
    project_name = "unknown"
    packages = []
    edges = []
    
    for line in lines:
        line = line.strip()
        
        # 跳过注释和空行
        if not line or line.startswith('#') or line.startswith('-'):
            continue
        
        # 解析包名和版本
        match = re.match(r'([a-zA-Z0-9_-]+)\s*(.*)?', line)
        if match:
            pkg_name = match.group(1).lower()
            constraint = match.group(2).strip() if match.group(2) else "*"
            
            # 提取版本号
            ver_match = re.search(r'[=<>!]+\s*([0-9][^,\s;]*)', constraint)
            version = ver_match.group(1) if ver_match else "0.0.0"
            
            packages.append(DependencyNode(
                name=pkg_name,
                version=version,
                ecosystem="pypi"
            ))
    
    return packages, edges


def parse_dependencies(project_path: str) -> tuple[List[DependencyNode], List[DependencyEdge], str]:
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
        logger.info("支持的依赖文件:")
        logger.info("  Python: pyproject.toml, requirements.txt, setup.py")
        logger.info("  Node.js: package.json")
        logger.info("  Java: pom.xml, build.gradle")
        logger.info("  Rust: Cargo.toml")
        logger.info("  Ruby: Gemfile")
        logger.info("  PHP: composer.json")
        logger.info("  .NET: *.csproj, *.fsproj, *.vbproj")
        logger.info("注: Go 和 C/C++ 无中央 registry，不在支持列表")
        sys.exit(1)

    filename = Path(dep_file).name

    # 根据文件名选择解析器
    # 注：detect_dependency_file 可识别 Gemfile/composer.json/.csproj 等，
    # 但 parsers 暂未实现自动解析。命中这些文件时下方会显式提示用户改用 query/search 子命令。
    parsers = {
        "pyproject.toml": (parse_pyproject_toml, "pypi"),
        "package.json": (parse_package_json, "npm"),
        "requirements.txt": (parse_requirements_txt, "pypi"),
    }

    if filename not in parsers:
        # 检查是否是 detect 支持但 parser 未实现的文件
        detect_supported_but_unparsed = {
            "pom.xml": "maven",
            "build.gradle": "maven",
            "build.gradle.kts": "maven",
            "Cargo.toml": "crates",
            "Gemfile": "rubygems",
            "composer.json": "packagist",
        }
        # 也检查 .csproj/.fsproj/.vbproj 扩展名
        suffix = Path(filename).suffix.lower()
        if suffix in (".csproj", ".fsproj", ".vbproj"):
            ecosystem_hint = "nuget"
        else:
            ecosystem_hint = detect_supported_but_unparsed.get(filename)

        if ecosystem_hint:
            logger.warning(
                f"已检测到 {filename}（ecosystem={ecosystem_hint}），"
                f"但自动解析器暂未实现。"
            )
            logger.info(
                f"请改用 query/search 子命令手动查询: "
                f"python dependency_analyzer.py query <pkg> -e {ecosystem_hint}"
            )
        else:
            logger.warning(f"暂不支持自动解析 {filename}")
            logger.info("提示: 目前支持自动解析 pyproject.toml, package.json, requirements.txt")
        sys.exit(1)
    
    parse_func, ecosystem = parsers[filename]
    
    logger.info(f"解析依赖文件: {filename}")
    packages, edges = parse_func(dep_file)
    
    if not packages:
        logger.error("未找到依赖信息")
        sys.exit(1)
    
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


def cmd_analyze_data(args):
    """分析依赖数据文件"""
    data_file = args.data_file
    data_path = Path(data_file)
    
    if not data_path.exists():
        logger.error(f"找不到文件 {data_file}")
        sys.exit(1)
    
    # 读取 JSON 数据
    try:
        with data_path.open('r', encoding='utf-8') as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        logger.error(f"解析 JSON 文件失败: {e}")
        sys.exit(1)
    
    # 验证数据格式
    if "packages" not in data or "edges" not in data:
        logger.error("JSON 文件必须包含 'packages' 和 'edges' 字段")
        sys.exit(1)
    
    logger.info(f"正在分析依赖数据: {data_file}")
    
    # 解析数据
    packages = []
    for pkg_data in data["packages"]:
        packages.append(DependencyNode(
            name=pkg_data["name"],
            version=pkg_data.get("version", "0.0.0"),
            ecosystem=pkg_data.get("ecosystem", "pypi"),
            is_root=pkg_data.get("is_root", False)
        ))
    
    edges = []
    for edge_data in data["edges"]:
        edges.append(DependencyEdge(
            source=edge_data["source"],
            target=edge_data["target"],
            constraint=edge_data.get("constraint", "*")
        ))
    
    logger.info(f"加载 {len(packages)} 个包, {len(edges)} 个依赖关系")
    
    # 创建分析器
    analyzer = DependencyAnalyzer()
    
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
        
        if args.updates:
            update_paths = analyzer.plan_update_paths()
            display_update_paths(update_paths)
        
        # 生成完整报告
        if args.report:
            root_pkg = packages[0].name if packages else "unknown"
            report = analyzer.generate_report(root_pkg)
            
            output_file = args.output if args.output else "dependency_report.json"
            analyzer.export_report_json(report, output_file)
            logger.info(f"报告已保存到: {output_file}")
        
        # 显示摘要
        if not any([args.conflicts, args.recommend, args.security, args.updates, args.report]):
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


def _to_deps_data(packages: List[DependencyNode],
                  edges: List[DependencyEdge]) -> dict:
    """
    将 DependencyNode/Edge 列表转为 deps_data dict schema

    用于 visualizer / readme_generator / impact_analyzer 等模块的输入
    （与 cmd_report 输入的 deps_data.json schema 一致）
    """
    return {
        "packages": [
            {
                "name": p.name,
                "version": p.version,
                "ecosystem": p.ecosystem,
                "is_root": p.is_root,
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


def cmd_analyze(args):
    """分析项目依赖"""
    project_path = args.project

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
        if getattr(args, 'visualize', False):
            import visualizer
            deps_data = _to_deps_data(packages, edges)
            depth = getattr(args, 'depth', 3) or 3
            mermaid = visualizer.render_mermaid_tree(deps_data, depth=depth)
            output_file = getattr(args, 'output', None)
            if output_file:
                out_path = Path(output_file)
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_path.write_text(mermaid, encoding='utf-8')
                logger.info(f"依赖树已写入: {output_file}")
            else:
                print(mermaid)

        # 冲突影响范围分析
        if getattr(args, 'impact', False):
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
            output_file = getattr(args, 'output', None)
            if output_file:
                out_path = Path(output_file)
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_path.write_text(
                    json.dumps(impacts, indent=2, ensure_ascii=False),
                    encoding='utf-8',
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
        if not any([args.conflicts, args.recommend, args.security, args.updates, args.report,
                    getattr(args, 'visualize', False), getattr(args, 'impact', False)]):
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

    # 根据生态系统选择脚本
    scripts = {
        "pypi": "pypi.py",
        "npm": "npm.py",
        "maven": "maven.py",
        "crates": "crates.py",
        "rubygems": "rubygems.py",
        "packagist": "packagist.py",
        "nuget": "nuget.py",
    }

    script_name = scripts.get(ecosystem)
    if not script_name:
        logger.error(f"不支持的生态系统 {ecosystem}")
        sys.exit(1)
    
    # 执行查询
    script_path = Path(__file__).parent / script_name
    
    import subprocess
    result = subprocess.run(
        [sys.executable, str(script_path), package_name],
        capture_output=True,
        text=True
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

    scripts = {
        "pypi": "pypi.py",
        "npm": "npm.py",
        "maven": "maven.py",
        "crates": "crates.py",
        "rubygems": "rubygems.py",
        "packagist": "packagist.py",
        "nuget": "nuget.py",
    }

    script_name = scripts.get(ecosystem)
    if not script_name:
        logger.error(f"不支持的生态系统 {ecosystem}")
        sys.exit(1)
    
    script_path = Path(__file__).parent / script_name
    
    import subprocess
    result = subprocess.run(
        [sys.executable, str(script_path), "--search", keyword],
        capture_output=True,
        text=True
    )
    
    if result.returncode == 0:
        print(result.stdout)
    else:
        logger.error(f"错误: {result.stderr}")
        sys.exit(1)


def cmd_security(args):
    """检查安全漏洞"""
    package_name = args.package

    print(f"正在检查包安全漏洞: {package_name}")
    print("=" * 70)

    # 查询包真实最新版本（避免用假版本导致 false positive）
    latest_version = None
    try:
        import json as _json
        import subprocess as _sp
        script_path = Path(__file__).parent / "pypi.py"
        result = _sp.run(
            [sys.executable, str(script_path), package_name],
            capture_output=True, text=True, timeout=60
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

    try:
        # 用真实版本创建 DependencyNode
        pkg = DependencyNode(
            name=package_name,
            version=latest_version,
            ecosystem="pypi"
        )

        packages = [pkg]
        edges = []

        analyzer.build_dependency_graph(packages, edges)

        # 检查漏洞
        vulns = analyzer.assess_security()

        if vulns:
            # --priority: 按 CVSS + exploit + business 加权排序
            if getattr(args, 'priority', False):
                import vulnerability_prioritizer
                vuln_dicts = [
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
                # 单包 security 查询：被检查的包本身视为根依赖
                deps_data = {
                    "packages": [
                        {"name": package_name, "version": latest_version,
                         "is_root": True, "ecosystem": "pypi"}
                    ],
                    "edges": [],
                }
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
    
    finally:
        analyzer.close()


def cmd_report(args):
    """生成完整报告（支持 json/html/pdf/sbom 格式）"""
    data_file = args.data_file
    fmt = getattr(args, 'format', 'json') or 'json'
    output_file = args.output  # 默认 None，按格式决定

    print(f"正在生成依赖报告: {data_file} (format={fmt})")
    print("=" * 70)

    data_path = Path(data_file)
    if not data_path.exists():
        logger.error(f"找不到文件 {data_file}")
        sys.exit(1)

    try:
        with data_path.open('r', encoding='utf-8') as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        logger.error(f"解析 JSON 文件失败: {e}")
        sys.exit(1)

    if "packages" not in data or "edges" not in data:
        logger.error("JSON 文件必须包含 'packages' 和 'edges' 字段")
        sys.exit(1)

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
    packages = []
    for pkg_data in data["packages"]:
        packages.append(DependencyNode(
            name=pkg_data["name"],
            version=pkg_data.get("version", "0.0.0"),
            ecosystem=pkg_data.get("ecosystem", "pypi"),
            is_root=pkg_data.get("is_root", False)
        ))

    edges = []
    for edge_data in data["edges"]:
        edges.append(DependencyEdge(
            source=edge_data["source"],
            target=edge_data["target"],
            constraint=edge_data.get("constraint", "*")
        ))

    analyzer = DependencyAnalyzer()
    try:
        analyzer.build_dependency_graph(packages, edges)
        report = analyzer.generate_report(
            packages[0].name if packages else "unknown"
        )
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
        report = analyzer.generate_report(
            packages[0].name if packages else "unknown"
        )
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
    if getattr(args, 'output', None):
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open('w', encoding='utf-8') as f:
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

    deps_data = _to_deps_data(packages, edges)

    # 用 EcosystemFetcher 查 registry 获取 description/license
    import readme_generator
    fetcher = readme_generator.EcosystemFetcher()
    markdown = readme_generator.generate_dependency_readme(deps_data, fetcher=fetcher)

    # 输出
    output_file = getattr(args, 'output', None)
    if output_file:
        out_path = Path(output_file)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(markdown, encoding='utf-8')
        print(f"依赖 README 已写入: {output_file}")
    else:
        print(markdown)


def cmd_simulate(args):
    """升级影响模拟（dry-run）"""
    package = args.package
    target_version = args.target_version
    project_path = getattr(args, 'project', None)

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

    output_file = getattr(args, 'output', None)
    if output_file:
        out_path = Path(output_file)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open('w', encoding='utf-8') as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
        print(f"模拟结果已写入: {output_file}")
    else:
        print(simulator.format_simulation_report(result))


def cmd_monitor(args):
    """漏洞持续监控"""
    project_path = args.project
    cron_schedule = getattr(args, 'cron', None)
    webhook_url = getattr(args, 'webhook', None)

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
    ts = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(scan_result['timestamp']))
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
        """
    )
    
    subparsers = parser.add_subparsers(dest="command", help="可用命令")
    
    # analyze-data 命令
    analyze_parser = subparsers.add_parser("analyze-data", help="分析依赖数据文件")
    analyze_parser.add_argument("data_file", help="JSON 格式的依赖数据文件")
    analyze_parser.add_argument("--conflicts", action="store_true", help="只检测冲突")
    analyze_parser.add_argument("--recommend", action="store_true", help="只获取版本推荐")
    analyze_parser.add_argument("--security", action="store_true", help="只检查安全漏洞")
    analyze_parser.add_argument("--updates", action="store_true", help="只显示更新路径")
    analyze_parser.add_argument("--report", action="store_true", help="生成完整报告")
    analyze_parser.add_argument("-o", "--output", help="报告输出文件路径")
    
    # analyze 命令（保留用于向后兼容）
    analyze_parser2 = subparsers.add_parser("analyze", help="分析项目依赖（旧版）")
    analyze_parser2.add_argument("project", help="项目路径或 pyproject.toml 路径")
    analyze_parser2.add_argument("--conflicts", action="store_true", help="只检测冲突")
    analyze_parser2.add_argument("--recommend", action="store_true", help="只获取版本推荐")
    analyze_parser2.add_argument("--security", action="store_true", help="只检查安全漏洞")
    analyze_parser2.add_argument("--updates", action="store_true", help="只显示更新路径")
    analyze_parser2.add_argument("--report", action="store_true", help="生成完整报告")
    analyze_parser2.add_argument("--visualize", action="store_true",
                                  help="渲染 Mermaid 依赖树（flowchart TD）")
    analyze_parser2.add_argument("--depth", type=int, default=3,
                                  help="依赖树渲染深度（默认 3，从根出发的依赖层数）")
    analyze_parser2.add_argument("--impact", action="store_true",
                                  help="分析冲突影响范围（反向追溯受影响包 + 依赖链）")
    analyze_parser2.add_argument("-o", "--output", help="报告输出文件路径")
    
    # query 命令
    query_parser = subparsers.add_parser("query", help="查询包信息")
    query_parser.add_argument("package", help="包名")
    query_parser.add_argument("-e", "--ecosystem", choices=["pypi", "npm", "maven", "crates", "rubygems", "packagist", "nuget"],
                             default="pypi", help="包生态系统 (默认: pypi)")

    # search 命令
    search_parser = subparsers.add_parser("search", help="搜索包")
    search_parser.add_argument("keyword", help="搜索关键词")
    search_parser.add_argument("-e", "--ecosystem", choices=["pypi", "npm", "maven", "crates", "rubygems", "packagist", "nuget"],
                              default="pypi", help="包生态系统 (默认: pypi)")
    
    # security 命令
    security_parser = subparsers.add_parser("security", help="检查安全漏洞")
    security_parser.add_argument("package", help="包名")
    security_parser.add_argument("--priority", action="store_true",
                                  help="按修复优先级排序（CVSS × 0.5 + exploit × 0.3 + business × 0.2）")
    
    # report 命令
    report_parser = subparsers.add_parser("report", help="生成完整报告（支持 json/html/pdf/sbom 格式）")
    report_parser.add_argument("data_file", help="JSON 格式的依赖数据文件")
    report_parser.add_argument("-o", "--output", default=None,
                              help="报告输出文件路径 (默认按格式决定: dependency_report.json / {project}-sbom.spdx.json)")
    report_parser.add_argument("--format", choices=["json", "html", "pdf", "sbom"],
                              default="json", help="报告格式 (默认: json)")

    # health 命令
    health_parser = subparsers.add_parser("health", help="依赖健康度评分（5 维度 + 雷达图）")
    health_parser.add_argument("project", help="项目路径或依赖文件路径")
    health_parser.add_argument("-o", "--output", default=None,
                              help="可选: 评分结果 JSON 输出路径")

    # readme 命令
    readme_parser = subparsers.add_parser("readme", help="生成项目依赖 README 章节（markdown）")
    readme_parser.add_argument("project", help="项目路径或依赖文件路径")
    readme_parser.add_argument("-o", "--output", default=None,
                               help="可选: markdown 输出路径（默认输出到 stdout）")

    # simulate 命令
    simulate_parser = subparsers.add_parser("simulate", help="升级影响模拟（dry-run）")
    simulate_parser.add_argument("package", help="待升级的包名")
    simulate_parser.add_argument("target_version", help="目标版本号")
    simulate_parser.add_argument("--project", default=None,
                                  help="项目路径（用于分析现有依赖图，可选）")
    simulate_parser.add_argument("-o", "--output", default=None,
                                  help="可选: JSON 输出路径（默认输出到 stdout）")

    # monitor 命令
    monitor_parser = subparsers.add_parser("monitor", help="漏洞持续监控")
    monitor_parser.add_argument("project", help="项目路径")
    monitor_parser.add_argument("--cron", default=None,
                                  help="生成 crontab 条目（如 '0 9 * * *'），不实际安装")
    monitor_parser.add_argument("--webhook", default=None,
                                  help="webhook URL，检测到新漏洞时 POST 告警")

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
    }
    
    commands[args.command](args)


if __name__ == "__main__":
    main()
