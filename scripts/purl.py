#!/usr/bin/env python3
"""Package URL (purl) 单点生成/解析模块（调研建议 R5，参照 syft purl 贯通）。

purl 规范: https://github.com/package-url/purl-spec
全部 SBOM（SPDX externalRefs / CycloneDX purl）与 OSV 查询共用本模块构造，
保证 interop 侧（osv-scanner --sbom / trivy sbom / deps.dev PurlLookup）
拿到一致的标识。

模块保持零第三方依赖（仅 urllib 标准库），可与 ecosystem_registry 一样被
重依赖失败即退出的链路安全 import。
"""

import logging
import re
from typing import Any, Dict, Optional
from urllib.parse import quote, unquote

import ecosystem_registry as eco_reg

logger = logging.getLogger(__name__)


def make_purl(name: str, ecosystem: str, version: Optional[str] = None) -> Optional[str]:
    """生成 purl 串；生态未知（注册表无 purl type）返回 None。

    - maven: 名字为 "groupId:artifactId" → pkg:maven/<group>/<artifact>@<version>；
      缺 group 时降级为无 namespace（记录 warning，不编造）
    - npm scoped 包 "@scope/pkg" → pkg:npm/%40scope/pkg（@ 按规范转义为 %40）
    - 其余生态：pkg:<type>/<name>[@<version>]，name/version 按 purl 规范转义
    """
    purl_type = eco_reg.purl_type(ecosystem)
    if not purl_type:
        return None

    if purl_type == "maven":
        if ":" in name:
            group, artifact = name.split(":", 1)
            namespace = quote(group.strip(), safe="")
            pname = quote(artifact.strip(), safe="")
        else:
            logger.warning(f"maven 包名缺 groupId（purl 无 namespace 降级）: {name}")
            namespace = ""
            pname = quote(name.strip(), safe="")
    elif purl_type == "npm" and name.startswith("@"):
        scope, _, pkg = name[1:].partition("/")
        if not scope or not pkg:
            logger.warning(f"npm scoped 包名非法: {name}")
            return None
        namespace = quote("@" + scope, safe="")
        pname = quote(pkg, safe="")
    elif purl_type == "composer" and "/" in name:
        # composer "vendor/pkg" → pkg:composer/vendor/pkg（vendor 为 namespace）
        vendor, _, pkg = name.partition("/")
        namespace = quote(vendor, safe="")
        pname = quote(pkg, safe="")
    else:
        namespace = ""
        pname = quote(name.strip(), safe="")

    purl = f"pkg:{purl_type}/"
    if namespace:
        purl += f"{namespace}/"
    purl += pname
    if version:
        purl += f"@{quote(str(version), safe='')}"
    return purl


def parse_purl(purl: str) -> Optional[Dict[str, Any]]:
    """解析 purl 串 → {ecosystem, name, version?}；非法串返回 None。

    内部生态名通过 purl type 反查 ecosystem_registry（crates↔cargo、
    rubygems↔gem、packagist↔composer 自动映射）。
    """
    if not isinstance(purl, str) or not purl.startswith("pkg:"):
        return None
    rest = purl[4:]
    # qualifiers(?…) 与 subpath(#…) 不属于 version，先剥离防污染
    rest = re.split(r"[?#]", rest, maxsplit=1)[0]
    version = None
    if "@" in rest:
        rest, _, raw_version = rest.rpartition("@")
        version = unquote(raw_version)
    parts = [p for p in rest.split("/") if p]
    if len(parts) < 2:
        return None
    purl_type = parts[0]
    ecosystem = _eco_from_purl_type(purl_type)
    if ecosystem is None:
        return None
    if len(parts) == 3:
        namespace, name = parts[1], parts[2]
    else:
        namespace, name = "", parts[1]
    if purl_type == "maven":
        if not namespace:
            return None  # maven purl 必须有 namespace（groupId）
        name = f"{unquote(namespace)}:{unquote(name)}"
    elif purl_type == "npm" and namespace:
        name = f"{unquote(namespace)}/{unquote(name)}"
    else:
        name = unquote(name)
        if namespace:
            name = f"{unquote(namespace)}/{name}"
    return {"ecosystem": ecosystem, "name": name, "version": version}


def _eco_from_purl_type(purl_type: str) -> Optional[str]:
    """purl type → 内部生态名（多对一：无；一对多：无）。"""
    for eco, meta in eco_reg.ECOSYSTEMS.items():
        if meta.get("purl_type") == purl_type:
            return eco
    return None


def depsdev_purl_path(purl: str) -> str:
    """deps.dev PurlLookup 的 URL path 片段：purl 整体百分号编码。

    注意（调研实测踩坑点）：deps.dev 要求 purl 作为整体做百分号编码
    （部分编码会 404），如 pkg%3Anpm%2F%2540babel%2Fcore%406.0.2。
    """
    return quote(purl, safe="")
