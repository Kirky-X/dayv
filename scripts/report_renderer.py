#!/usr/bin/env python3
"""
Report Renderer - 报告渲染器
将 dependency_analyzer.export_report_json 的 schema 渲染为 HTML / PDF / JSON

设计契约:
- 输入: report_dict (与 export_report_json 输出 schema 一致)
- 输出: HTML 字符串 / PDF 文件 / JSON 文件
- HTML 必须支持中文 (UTF-8)、表格可排序、防 XSS
- PDF 依赖 weasyprint，不可用时显式报错 (Rule 12)
- JSON 保持向后兼容
"""

import json
import logging
from pathlib import Path

from jinja2 import BaseLoader, Environment

logger = logging.getLogger(__name__)

# ============ HTML 模板（内嵌，避免外部文件依赖） ============

_HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>依赖分析报告 - {{ report.root_package }}</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
                         "Helvetica Neue", Arial, "PingFang SC", "Microsoft YaHei", sans-serif;
            margin: 2em; color: #333; line-height: 1.6;
        }
        h1 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 0.3em; }
        h2 { color: #34495e; margin-top: 1.8em; border-left: 4px solid #3498db; padding-left: 0.5em; }
        .summary-grid {
            display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 1em; margin: 1em 0;
        }
        .summary-card {
            background: #f8f9fa; padding: 1em; border-radius: 4px;
            border-left: 4px solid #3498db;
        }
        .summary-card .label { color: #7f8c8d; font-size: 0.85em; text-transform: uppercase; }
        .summary-card .value { font-size: 1.6em; font-weight: bold; color: #2c3e50; margin-top: 0.2em; }
        table { width: 100%; border-collapse: collapse; margin: 1em 0; background: #fff; }
        th, td { padding: 0.7em 0.9em; text-align: left; border-bottom: 1px solid #e0e0e0; }
        th { background: #ecf0f1; cursor: pointer; user-select: none; position: relative; }
        th:hover { background: #d5dbdb; }
        th::after { content: " ⇅"; color: #95a5a6; font-size: 0.8em; }
        .severity-critical, .severity-high { color: #e74c3c; font-weight: bold; }
        .severity-medium { color: #f39c12; font-weight: bold; }
        .severity-low { color: #27ae60; }
        .empty-state { color: #95a5a6; font-style: italic; padding: 1em; background: #f8f9fa; border-radius: 4px; }
        .recommendations {
            background: #fff3cd; padding: 1em 1.5em; border-radius: 4px;
            border-left: 4px solid #f39c12; margin: 1em 0;
        }
        .recommendations ul { margin: 0.5em 0; padding-left: 1.5em; }
        .footer { margin-top: 2em; padding-top: 1em; border-top: 1px solid #ddd; color: #7f8c8d; font-size: 0.85em; }
        .tag { display: inline-block; padding: 0.2em 0.6em; border-radius: 3px; font-size: 0.85em; background: #ecf0f1; color: #2c3e50; }
        .tag-high { background: #fdecea; color: #e74c3c; }
        .tag-medium { background: #fef5e7; color: #f39c12; }
        .tag-low { background: #eafaf1; color: #27ae60; }
        .tag-critical { background: #fdecea; color: #c0392b; }
    </style>
    <script>
        function sortTable(tableId, colIdx) {
            const table = document.getElementById(tableId);
            if (!table) return;
            const tbody = table.querySelector('tbody');
            if (!tbody) return;
            const rows = Array.from(tbody.querySelectorAll('tr'));
            const sorted = rows.sort((a, b) => {
                const aCell = (a.cells[colIdx] || {}).textContent || '';
                const bCell = (b.cells[colIdx] || {}).textContent || '';
                return aCell.trim().localeCompare(bCell.trim(), 'zh-Hans-CN', {numeric: true});
            });
            // 切换升序/降序
            if (table.dataset.sortDir === 'asc') {
                sorted.reverse();
                table.dataset.sortDir = 'desc';
            } else {
                table.dataset.sortDir = 'asc';
            }
            sorted.forEach(r => tbody.appendChild(r));
        }
    </script>
</head>
<body>
    <h1>依赖分析报告</h1>

    <h2>项目概览</h2>
    <div class="summary-grid">
        <div class="summary-card">
            <div class="label">项目名称</div>
            <div class="value">{{ report.root_package }}</div>
        </div>
        <div class="summary-card">
            <div class="label">总包数</div>
            <div class="value">{{ report.summary.total_packages }}</div>
        </div>
        <div class="summary-card">
            <div class="label">依赖关系</div>
            <div class="value">{{ report.summary.total_dependencies }}</div>
        </div>
        <div class="summary-card">
            <div class="label">冲突数</div>
            <div class="value">{{ report.summary.conflicts }}</div>
        </div>
        <div class="summary-card">
            <div class="label">漏洞数</div>
            <div class="value">{{ report.summary.vulnerabilities }}</div>
        </div>
        <div class="summary-card">
            <div class="label">可更新</div>
            <div class="value">{{ report.summary.update_paths }}</div>
        </div>
    </div>

    <h2>依赖列表</h2>
    <p>共 {{ report.summary.total_packages }} 个包，{{ report.summary.total_dependencies }} 条依赖关系。</p>

    <h2>冲突检测结果</h2>
    {% if report.conflicts %}
    <table class="sortable" id="conflicts-table">
        <thead>
            <tr>
                <th onclick="sortTable('conflicts-table', 0)">包名</th>
                <th onclick="sortTable('conflicts-table', 1)">冲突类型</th>
                <th onclick="sortTable('conflicts-table', 2)">严重级别</th>
                <th onclick="sortTable('conflicts-table', 3)">来源</th>
                <th onclick="sortTable('conflicts-table', 4)">建议</th>
            </tr>
        </thead>
        <tbody>
        {% for c in report.conflicts %}
            <tr>
                <td>{{ c.package }}</td>
                <td>{{ c.conflict_type }}</td>
                <td><span class="tag tag-{{ c.severity }}">{{ c.severity }}</span></td>
                <td>
                    {% for rb in c.required_by %}
                        {{ rb.package }} ({{ rb.constraint }}){% if not loop.last %}<br>{% endif %}
                    {% endfor %}
                </td>
                <td>{{ c.suggestion }}</td>
            </tr>
        {% endfor %}
        </tbody>
    </table>
    {% else %}
    <div class="empty-state">✅ 无冲突</div>
    {% endif %}

    <h2>漏洞检测结果</h2>
    {% if report.vulnerabilities %}
    <table class="sortable" id="vulns-table">
        <thead>
            <tr>
                <th onclick="sortTable('vulns-table', 0)">CVE ID</th>
                <th onclick="sortTable('vulns-table', 1)">包名</th>
                <th onclick="sortTable('vulns-table', 2)">影响版本</th>
                <th onclick="sortTable('vulns-table', 3)">严重级别</th>
                <th onclick="sortTable('vulns-table', 4)">修复版本</th>
                <th onclick="sortTable('vulns-table', 5)">描述</th>
            </tr>
        </thead>
        <tbody>
        {% for v in report.vulnerabilities %}
            <tr>
                <td>{{ v.cve_id }}</td>
                <td>{{ v.package }}</td>
                <td>{{ v.version }}</td>
                <td><span class="tag tag-{{ v.severity }}">{{ v.severity }}</span></td>
                <td>{{ v.fixed_version or 'N/A' }}</td>
                <td>{{ v.description }}</td>
            </tr>
        {% endfor %}
        </tbody>
    </table>
    {% else %}
    <div class="empty-state">✅ 无漏洞</div>
    {% endif %}

    {% if report.license_violations %}
    <h2>许可证合规</h2>
    <p>{{ report.license_violations|length }} 个依赖不在白名单，{{ (report.license_unknown or [])|length }} 个许可证未知（单列，不算通过）。</p>
    <table class="sortable" id="license-table">
        <thead>
            <tr>
                <th onclick="sortTable('license-table', 0)">包名</th>
                <th onclick="sortTable('license-table', 1)">许可证</th>
                <th onclick="sortTable('license-table', 2)">分类</th>
            </tr>
        </thead>
        <tbody>
        {% for v in report.license_violations %}
            <tr>
                <td>{{ v.package }}</td>
                <td>{{ v.license }}</td>
                <td><span class="tag tag-{{ 'high' if v.category == 'copyleft' else 'medium' }}">{{ v.category }}</span></td>
            </tr>
        {% endfor %}
        </tbody>
    </table>
    {% if report.license_unknown %}
    <div class="empty-state">⚠️ 无法校验（license 未知）: {% for u in report.license_unknown %}{{ u.package }}{% if not loop.last %}、{% endif %}{% endfor %}</div>
    {% endif %}
    {% endif %}

    <h2>版本推荐结果</h2>
    {% if report.update_paths %}
    <table class="sortable" id="updates-table">
        <thead>
            <tr>
                <th onclick="sortTable('updates-table', 0)">包名</th>
                <th onclick="sortTable('updates-table', 1)">当前版本</th>
                <th onclick="sortTable('updates-table', 2)">目标版本</th>
                <th onclick="sortTable('updates-table', 3)">迁移步骤</th>
                <th onclick="sortTable('updates-table', 4)">建议</th>
            </tr>
        </thead>
        <tbody>
        {% for u in report.update_paths %}
            <tr>
                <td>{{ u.package }}</td>
                <td>{{ u.current_version }}</td>
                <td>{{ u.target_version }}</td>
                <td>
                    <ul>
                    {% for s in u.steps %}
                        <li>{{ s }}</li>
                    {% endfor %}
                    </ul>
                </td>
                <td>{{ u.recommendation }}</td>
            </tr>
        {% endfor %}
        </tbody>
    </table>
    {% else %}
    <div class="empty-state">✅ 无需更新</div>
    {% endif %}

    {% if report.recommendations %}
    <div class="recommendations">
        <strong>📌 改进建议:</strong>
        <ul>
        {% for r in report.recommendations %}
            <li>{{ r }}</li>
        {% endfor %}
        </ul>
    </div>
    {% endif %}

    <div class="footer">
        报告生成时间: {{ report.timestamp | strftime('%Y-%m-%d %H:%M:%S') }} · 由 dayv 依赖分析引擎生成
    </div>
</body>
</html>"""


# ============ 渲染函数 ============


def render_html(report: dict) -> str:
    """
    渲染报告为 HTML 字符串

    Args:
        report: 与 export_report_json 输出 schema 一致的字典

    Returns:
        HTML 字符串（UTF-8，含可排序表格，防 XSS）
    """
    env = Environment(loader=BaseLoader(), autoescape=True)
    # 注册 strftime 过滤器（Jinja2 默认不带）
    env.filters['strftime'] = lambda ts, fmt: _format_timestamp(ts, fmt)
    template = env.from_string(_HTML_TEMPLATE)
    return template.render(report=report)


def _format_timestamp(ts: float, fmt: str) -> str:
    """格式化时间戳"""
    import time
    try:
        return time.strftime(fmt, time.localtime(ts))
    except (ValueError, TypeError):
        return str(ts)


def render_pdf(report: dict, output_path: str) -> str:
    """
    渲染报告为 PDF 文件（依赖 weasyprint）

    Args:
        report: 报告字典
        output_path: PDF 输出路径

    Returns:
        PDF 文件路径

    Raises:
        RuntimeError: weasyprint 未安装时抛出（含安装提示）
    """
    try:
        import weasyprint
    except ImportError as e:
        raise RuntimeError(
            "PDF 输出需要 weasyprint 库。请安装: pip install weasyprint "
            "(系统依赖: apt install libpango-1.0-0 libpangoft2-1.0-0)"
        ) from e

    html_str = render_html(report)
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    weasyprint.HTML(string=html_str, encoding="utf-8").write_pdf(str(output))
    logger.info(f"PDF 报告已生成: {output_path}")
    return output_path


def render_json(report: dict, output_path: str) -> str:
    """
    渲染报告为 JSON 文件（向后兼容 export_report_json）

    Args:
        report: 报告字典
        output_path: JSON 输出路径

    Returns:
        JSON 文件路径
    """
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open('w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    logger.info(f"JSON 报告已生成: {output_path}")
    return output_path


# ============ SARIF 2.1.0（R15，参照 osv-scanner；可直接喂
# github/codeql-action/upload-sarif 进 GitHub Security 页） ============

_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
}


def render_sarif(report: dict) -> dict:
    """
    渲染报告为 SARIF 2.1.0 dict。

    - 每个漏洞组一条 rule（ruleId=CVE/OSV id；dayv 解析时 aliases 已合并为
      单一 cve_id，天然满足"aliases 合并为一条 rule"）
    - level 按 severity 映射：critical/high→error、medium→warning、low→note
    - message 含包名@版本与修复版本
    """
    vulns = report.get("vulnerabilities", []) or []
    rules = []
    results = []
    seen_rules = set()
    for v in vulns:
        rule_id = v.get("cve_id") or "UNKNOWN-VULN"
        severity = (v.get("severity", "low") or "low").lower()
        level = _SARIF_LEVEL.get(severity, "note")
        if rule_id not in seen_rules:
            seen_rules.add(rule_id)
            rules.append(
                {
                    "id": rule_id,
                    "name": rule_id,
                    "shortDescription": {
                        "text": f"{rule_id} 影响 {v.get('package', '?')}"
                    },
                    "helpUri": f"https://osv.dev/vulnerability/{rule_id}",
                    "defaultConfiguration": {"level": level},
                    "properties": {"severity": severity},
                }
            )
        message = f"{v.get('package', '?')}@{v.get('version', '')} 受 {rule_id} 影响"
        if v.get("fixed_version"):
            message += f"，修复版本 {v['fixed_version']}"
        # locations 省略：dayv 是 registry 级扫描无文件级定位，
        # "pkg@ver" 不是合法文件 URI，写了反而在 GitHub Security 页显示异常
        results.append(
            {
                "ruleId": rule_id,
                "level": level,
                "message": {"text": message},
            }
        )
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "dayv",
                        "informationUri": "https://github.com/Kirky-X/dayv",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


def _write_json_file(payload: dict, output_path: str, log_label: str) -> str:
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
    logger.info(f"{log_label} 已生成: {output_path}")
    return output_path


def render_report(report: dict, output_path: str, fmt: str = "json") -> str:
    """
    按格式分派渲染器

    Args:
        report: 报告字典
        output_path: 输出文件路径
        fmt: 格式 (json / html / pdf)

    Returns:
        输出文件路径

    Raises:
        ValueError: 未知格式
    """
    fmt_lower = (fmt or "json").lower()
    if fmt_lower == "json":
        return render_json(report, output_path)
    elif fmt_lower == "html":
        html_str = render_html(report)
        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open('w', encoding='utf-8') as f:
            f.write(html_str)
        logger.info(f"HTML 报告已生成: {output_path}")
        return output_path
    elif fmt_lower == "pdf":
        return render_pdf(report, output_path)
    elif fmt_lower == "sarif":
        return _write_json_file(render_sarif(report), output_path, "SARIF 报告")
    else:
        raise ValueError(
            f"不支持的报告格式: {fmt}。支持的格式: json, html, pdf, sarif"
        )
