#!/usr/bin/env python3
"""
BaseEcosystemAdapter — 7 ecosystem 包查询子脚本的共享基类。

去重 pypi / npm / maven / crates / rubygems / packagist / nuget 子脚本中
~70% 的结构重复（main CLI 调度 + get_package/search_packages 骨架）。

统一输出 schema（与各 parse_package_info 既定契约一致）：
    {
        "name": str,
        "description": str,
        "latest_version": str,
        "versions": [{"version": str, "date": str}, ...],
        "dependencies": {name: constraint, ...},
        "download_url": str,
        "license": str,
        "homepage": str,
    }

子类只需实现 ecosystem 特异逻辑（4 个抽象方法）：
    build_package_url / build_search_url / parse_package_info / parse_search_results

可选 hook（按需覆盖）：
    post_fetch(name, raw)        — rubygems 用：再取 dependencies 端点合并
    validate_package_arg(arg)    — maven / packagist 用：校验 g:a / vendor/package
    split_package_arg(arg)       — maven 用：拆 g:a → (group_id, artifact_id)

缓存：每个子脚本在模块级定义 @lru_cache 的 _fetch_cached（resolve 模块级 fetch_json/fetch_html，
兼容 patch.object 测试），构造 adapter 时注入 fetcher=_fetch_cached。
"""

import json
import sys
from typing import Any, Callable


class BaseEcosystemAdapter:
    """7 ecosystem 适配器基类。子脚本继承并实现 4 个抽象方法。"""

    # ---- 类属性（子类覆盖）----
    ECOSYSTEM_NAME: str = ""  # "pypi" / "npm" / ...（用于 usage 文案）

    # CLI usage 文案
    PACKAGE_USAGE_HINT: str = "<package-name>"
    SEARCH_USAGE_HINT: str = "<keyword>"
    # PACKAGE_FORMAT_HINT 用于 usage 行（如 maven 的 "<groupId>:<artifactId>"）
    PACKAGE_FORMAT_HINT: str = ""
    # PACKAGE_FORMAT_ERROR 非 None 时，main 会先调用 validate_package_arg；
    # 校验失败打印此错误并 sys.exit(1)
    PACKAGE_FORMAT_ERROR: str = ""

    def __init__(self, fetcher: Callable[[str], Any]):
        """
        Args:
            fetcher: callable(url) -> raw，通常为模块级 @lru_cache 包装的 fetch 函数。
                     注入而非硬绑，便于测试替换与 patch.object 生效。
        """
        self._fetcher = fetcher

    # ============ 抽象方法（子类必须实现）============

    def build_package_url(self, *args: str) -> str:
        """构造包详情 URL。args 为 get_package 的位置参数（maven 是 (group, artifact)）。"""
        raise NotImplementedError

    def parse_package_info(self, raw: Any, *args: str) -> dict:
        """解析包详情响应为统一 schema dict。"""
        raise NotImplementedError

    def build_search_url(self, keyword: str) -> str:
        """构造搜索 URL。"""
        raise NotImplementedError

    def parse_search_results(self, raw: Any) -> dict:
        """解析搜索响应为 {total, results} dict。"""
        raise NotImplementedError

    # ============ 可选 hook（子类按需覆盖）============

    def post_fetch(self, name: str, raw: Any) -> Any:
        """主端点 fetch 后、parse 前的额外处理（rubygems: 再取 deps 合并）。默认透传。"""
        return raw

    def validate_package_arg(self, arg: str) -> bool:
        """CLI 包参数校验。默认 True（不校验）。maven/packagist 覆盖。"""
        return True

    def split_package_arg(self, arg: str) -> tuple:
        """把 CLI 单参数拆成 get_package 的位置参数元组。默认 (arg,)。maven 覆盖为 (g, a)。"""
        return (arg,)

    # ============ 共享实现 ============

    def get_package(self, *args: str) -> dict:
        """
        获取包详情：build URL → cached fetch → post_fetch → parse。

        Args:
            *args: 包标识参数（多数 ecosystem 为 (name,)；maven 为 (group_id, artifact_id)）

        Returns:
            统一 schema dict
        """
        url = self.build_package_url(*args)
        raw = self._fetcher(url)
        # name 取最后一个位置参数（maven 用 artifact_id，其它即 name）
        name = args[-1] if args else ""
        raw = self.post_fetch(name, raw)
        return self.parse_package_info(raw, *args)

    def search_packages(self, keyword: str) -> dict:
        """搜索包：build URL → cached fetch → parse。"""
        url = self.build_search_url(keyword)
        raw = self._fetcher(url)
        return self.parse_search_results(raw)

    def main(self) -> None:
        """CLI 调度入口。各子脚本的 `main` 绑定到此方法。"""
        if len(sys.argv) < 2:
            pkg_hint = self.PACKAGE_FORMAT_HINT or self.PACKAGE_USAGE_HINT
            print("Usage:")
            print(f"  python {self.ECOSYSTEM_NAME}.py {pkg_hint}       # 查询包详情")
            print(
                f"  python {self.ECOSYSTEM_NAME}.py --search {self.SEARCH_USAGE_HINT}   # 搜索包"
            )
            sys.exit(1)

        if sys.argv[1] == "--search":
            if len(sys.argv) < 3:
                print("Error: 请提供搜索关键词")
                sys.exit(1)
            result = self.search_packages(sys.argv[2])
        else:
            arg = sys.argv[1]
            if self.PACKAGE_FORMAT_ERROR and not self.validate_package_arg(arg):
                print(f"Error: {self.PACKAGE_FORMAT_ERROR}")
                sys.exit(1)
            result = self.get_package(*self.split_package_arg(arg))

        print(json.dumps(result, indent=2, ensure_ascii=False))
