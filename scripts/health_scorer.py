#!/usr/bin/env python3
"""
Health Scorer - 依赖健康度评分器
基于 dependency_analyzer 的分析报告计算 5 维度健康度评分

5 个维度（加权平均）:
1. version_freshness    (权重 0.20) - 版本新旧度
2. vulnerability_status (权重 0.30) - 漏洞状态
3. maintenance_status   (权重 0.15) - 维护状态
4. dependency_stability (权重 0.20) - 依赖稳定性
5. license_compliance   (权重 0.15) - 许可证合规性

阈值:
- >=70: healthy
- 50-69: warning
- <50: danger
"""

import logging
from typing import Dict, List

logger = logging.getLogger(__name__)

# ============ 常量（确定性配置，不交给模型判断） ============

# 漏洞严重级别 → 单个漏洞扣分值
SEVERITY_PENALTY = {
    "critical": 40,
    "high": 25,
    "medium": 20,
    "low": 5,
}

# 维度权重（总和 = 1.0）
DIMENSION_WEIGHTS = {
    "version_freshness": 0.20,
    "vulnerability_status": 0.30,
    "maintenance_status": 0.15,
    "dependency_stability": 0.20,
    "license_compliance": 0.15,
}

# 单个冲突的扣分值
CONFLICT_PENALTY = 25

# 单个弃用包的维护维度扣分（R15：npm deprecated / crates yanked）
DEPRECATED_PENALTY = 10
DEPRECATED_PENALTY_CAP = 30

# 阈值
THRESHOLD_HEALTHY = 70
THRESHOLD_WARNING = 50

# 维度中文名（用于改进建议）
DIMENSION_NAMES = {
    "version_freshness": "版本新旧度",
    "vulnerability_status": "漏洞状态",
    "maintenance_status": "维护状态",
    "dependency_stability": "依赖稳定性",
    "license_compliance": "许可证合规性",
}

# 维度排序（雷达图轴顺序）
RADAR_AXES = [
    "version_freshness",
    "vulnerability_status",
    "maintenance_status",
    "dependency_stability",
    "license_compliance",
]


# ============ 维度评分函数 ============


def _score_version_freshness(report: dict) -> float:
    """
    版本新旧度评分：基于需要更新的包占比

    逻辑: outdated_ratio = update_paths / total_packages
          score = 100 * (1 - outdated_ratio)
    """
    total = report.get("summary", {}).get("total_packages", 0)
    if total == 0:
        return 100.0
    updates = len(report.get("update_paths", []))
    outdated_ratio = min(updates / total, 1.0)
    return round(100.0 * (1 - outdated_ratio), 1)


def _score_vulnerability(report: dict) -> float:
    """
    漏洞状态评分：基于 CVE 数量 × 严重级别扣分

    逻辑: penalty = sum(SEVERITY_PENALTY[v.severity] for v in vulns)
          score = max(0, 100 - penalty)
    """
    vulns = report.get("vulnerabilities", [])
    penalty = 0
    for v in vulns:
        severity = (v.get("severity", "low") or "low").lower()
        penalty += SEVERITY_PENALTY.get(severity, SEVERITY_PENALTY["low"])
    return max(0.0, 100.0 - penalty)


def _score_maintenance(report: dict) -> float:
    """
    维护状态评分：基于是否有更新活动 + 是否无漏洞 + 弃用包扣分（R15）

    逻辑:
      - base = 50
      - 有 update_paths（说明项目活跃可升级）: +25
      - 无漏洞（说明维护质量好）: +25
      - 弃用包: 每个 -10（上限 -30）
      - 上限 100，下限 0
    """
    total = report.get("summary", {}).get("total_packages", 0)
    if total == 0:
        return 75.0  # 无数据时中性分

    base = 50.0
    if len(report.get("update_paths", [])) > 0:
        base += 25.0
    if not report.get("vulnerabilities"):
        base += 25.0
    deprecated_count = len(report.get("deprecated_packages") or [])
    if deprecated_count:
        base -= min(
            DEPRECATED_PENALTY_CAP, deprecated_count * DEPRECATED_PENALTY
        )
    return max(0.0, min(100.0, base))


def _score_stability(report: dict) -> float:
    """
    依赖稳定性评分：基于冲突数量扣分

    逻辑: score = max(0, 100 - conflicts * CONFLICT_PENALTY)
    """
    conflicts = report.get("conflicts", [])
    return max(0.0, 100.0 - len(conflicts) * CONFLICT_PENALTY)


def _score_license(report: dict) -> float:
    """
    许可证合规性评分：按依赖包的真实许可证数据评分

    license_info 条目支持两种格式：
      - {"package": name, "license": str}（report_to_dict 产出的标准格式，
        无法获取 license 的包 license 为 "UNKNOWN"）
      - 纯字符串（向后兼容旧调用方）

    评分:
      - MIT/Apache-2.0/BSD/ISC: 100
      - LGPL/MPL: 70
      - GPL/AGPL: 40
      - UNKNOWN/空/其他: 50（未知许可证按保守中性风险计分）
    无 license_info 数据（未采集）时返回中性分 75.0
    """
    license_info = report.get("license_info")
    if not license_info:
        return 75.0

    # 按许可证列表评分
    scores = []
    for item in license_info:
        lic = item.get("license", "") if isinstance(item, dict) else (item or "")
        lic_upper = (lic or "").strip().upper()
        if not lic_upper or lic_upper == "UNKNOWN":
            scores.append(50.0)
        elif any(x in lic_upper for x in ["MIT", "APACHE-2.0", "BSD", "ISC"]):
            scores.append(100.0)
        elif any(x in lic_upper for x in ["LGPL", "MPL"]):
            scores.append(70.0)
        elif any(x in lic_upper for x in ["GPL", "AGPL"]):
            scores.append(40.0)
        else:
            scores.append(50.0)
    return round(sum(scores) / len(scores), 1) if scores else 75.0


# ============ 主函数 ============


def score_health(report: dict) -> dict:
    """
    计算依赖健康度评分

    Args:
        report: dependency_analyzer.generate_report() 导出的报告字典
                必须含 summary / conflicts / vulnerabilities / update_paths

    Returns:
        {
            "total_score": float,        # 0-100
            "dimensions": {              # 5 维度分数
                "version_freshness": float,
                "vulnerability_status": float,
                "maintenance_status": float,
                "dependency_stability": float,
                "license_compliance": float,
            },
            "suggestions": List[str],    # 改进建议
            "level": str,                # healthy / warning / danger
        }
    """
    dims = {
        "version_freshness": _score_version_freshness(report),
        "vulnerability_status": _score_vulnerability(report),
        "maintenance_status": _score_maintenance(report),
        "dependency_stability": _score_stability(report),
        "license_compliance": _score_license(report),
    }

    # 加权平均
    total = sum(dims[k] * DIMENSION_WEIGHTS[k] for k in dims)
    total = round(total, 1)

    # 阈值判定
    if total >= THRESHOLD_HEALTHY:
        level = "healthy"
    elif total >= THRESHOLD_WARNING:
        level = "warning"
    else:
        level = "danger"

    suggestions = _generate_suggestions(dims, report)

    return {
        "total_score": total,
        "dimensions": dims,
        "suggestions": suggestions,
        "level": level,
    }


def _generate_suggestions(dims: Dict[str, float], report: dict) -> List[str]:
    """针对最低分维度生成改进建议"""
    suggestions = []

    # 弃用包（R15）：无论哪个维度最低都显性提示（维护风险独立于分数）
    deprecated = report.get("deprecated_packages") or []
    if deprecated:
        names = ", ".join(p.get("package", "?") for p in deprecated[:5])
        more = f" 等 {len(deprecated)} 个" if len(deprecated) > 5 else ""
        suggestions.append(
            f"检测到弃用依赖: {names}{more}（npm deprecated / crates yanked），"
            "建议规划替换方案"
        )

    # 找最低分维度
    lowest_name = min(dims, key=lambda k: dims[k])
    lowest_score = dims[lowest_name]
    lowest_cn = DIMENSION_NAMES[lowest_name]

    # 针对最低维度给具体建议
    if lowest_name == "vulnerability_status":
        suggestions.append(
            f"漏洞状态得分最低（{lowest_score}），建议立即修复 CVE 并升级到 fixed_version"
        )
    elif lowest_name == "version_freshness":
        suggestions.append(
            f"版本新旧度最低（{lowest_score}），建议升级过时依赖到最新稳定版"
        )
    elif lowest_name == "dependency_stability":
        suggestions.append(
            f"依赖稳定性最低（{lowest_score}），建议统一冲突包的版本约束"
        )
    elif lowest_name == "maintenance_status":
        suggestions.append(
            f"维护状态较低（{lowest_score}），建议检查上游包的活跃度，下线无人维护的依赖"
        )
    elif lowest_name == "license_compliance":
        suggestions.append(
            f"许可证合规性较低（{lowest_score}），建议核查 GPL/AGPL 等限制性许可证"
        )

    # 任何低于 50 的非最低维度也给建议
    for name in RADAR_AXES:
        if name == lowest_name:
            continue
        if dims[name] < THRESHOLD_WARNING:
            cn = DIMENSION_NAMES[name]
            suggestions.append(
                f"维度 {cn}（{name}）得分 {dims[name]} 低于阈值 {THRESHOLD_WARNING}，建议关注"
            )

    return suggestions


# ============ 雷达图渲染 ============


def render_radar_mermaid(score_result: dict) -> str:
    """
    渲染 Mermaid 雷达图（XYChart 模拟，5 维度柱状图）

    Args:
        score_result: score_health() 返回的字典

    Returns:
        Mermaid 代码块字符串
    """
    dims = score_result["dimensions"]
    total = score_result["total_score"]

    # x-axis 用英文 key（与 dimensions 字段名一致，便于程序化解析）
    # title 中附带中文映射供人类阅读
    lines = [
        "```mermaid",
        "xychart-beta",
        f'    title "依赖健康度评分 - 总分 {total} ({score_result["level"]})"',
        '    x-axis ["version_freshness(版本新旧)", "vulnerability_status(漏洞状态)", '
        '"maintenance_status(维护状态)", "dependency_stability(依赖稳定)", "license_compliance(许可证合规)"]',
        '    y-axis "Score" 0 --> 100',
        "    bar [",
    ]
    for name in RADAR_AXES:
        lines.append(f"      {dims[name]}")
    lines.append("    ]")
    lines.append("```")
    return "\n".join(lines)
