#!/usr/bin/env python3
"""R8 许可证白名单合规校验回归测试（调研报告建议 8 验收项）。

验收点：
- 含 GPL 依赖的 license_info + --allowed-licenses MIT → violations 含该包
- UNKNOWN 显式单列（不算通过也不算违规）
- 分类字典 YAML/JSON 覆盖（扩充/迁移类别）
- 表达式（OR / WITH）任一分支命中白名单即合规
"""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

import license_policy as lp


class TestClassify:
    def test_builtin_categories(self):
        assert lp.classify_license("MIT") == "permissive"
        assert lp.classify_license("Apache-2.0") == "permissive"
        assert lp.classify_license("LGPL-2.1-only") == "weak_copyleft"
        assert lp.classify_license("MPL-2.0") == "weak_copyleft"
        assert lp.classify_license("GPL-3.0-only") == "copyleft"
        assert lp.classify_license("AGPL-3.0") == "copyleft"

    def test_unknown_and_empty(self):
        assert lp.classify_license("") == "UNKNOWN"
        assert lp.classify_license("UNKNOWN") == "UNKNOWN"
        assert lp.classify_license("Proprietary-License-X") == "UNKNOWN"

    def test_dual_license_takes_strictest(self):
        assert lp.classify_license("MIT OR GPL-3.0") == "copyleft"

    def test_custom_override_moves_license(self):
        custom = {"permissive": ["GPL-2.0"]}  # 内部政策把 GPL-2.0 视为可用
        assert lp.classify_license("GPL-2.0-only", custom) == "permissive"


class TestEvaluatePolicy:
    LICENSE_INFO = [
        {"package": "ok-mit", "license": "MIT"},
        {"package": "bad-gpl", "license": "GPL-3.0-only"},
        {"package": "dual", "license": "MIT OR Apache-2.0"},
        {"package": "mystery", "license": "UNKNOWN"},
        {"package": "blank", "license": ""},
    ]

    def test_gpl_violates_mit_whitelist(self):
        result = lp.evaluate_license_policy(self.LICENSE_INFO, ["MIT"])
        assert [v["package"] for v in result["license_violations"]] == ["bad-gpl"]
        assert result["license_violations"][0]["category"] == "copyleft"

    def test_unknown_bucketed_separately(self):
        result = lp.evaluate_license_policy(self.LICENSE_INFO, ["MIT"])
        assert {u["package"] for u in result["unknown"]} == {"mystery", "blank"}

    def test_or_expression_any_branch_passes(self):
        result = lp.evaluate_license_policy(self.LICENSE_INFO, ["MIT"])
        assert "dual" not in [v["package"] for v in result["license_violations"]]

    def test_apache_whitelist(self):
        result = lp.evaluate_license_policy(self.LICENSE_INFO, ["Apache-2.0", "MIT"])
        # MIT/Apache 白名单下仅 GPL 依赖违规
        assert [v["package"] for v in result["license_violations"]] == ["bad-gpl"]

    def test_with_clause_stripped(self):
        info = [{"package": "lib", "license": "GPL-2.0 WITH Classpath-exception-2.0"}]
        result = lp.evaluate_license_policy(info, ["MIT"])
        assert [v["package"] for v in result["license_violations"]] == ["lib"]
        info2 = [{"package": "lib", "license": "GPL-2.0 WITH Classpath-exception-2.0"}]
        result2 = lp.evaluate_license_policy(info2, ["GPL-2.0"])
        assert result2["license_violations"] == []


class TestCustomCategories:
    def test_json_override(self, tmp_path):
        f = tmp_path / "cats.json"
        f.write_text(
            json.dumps({"permissive": ["INTERNAL-Proprietary"]}), encoding="utf-8"
        )
        custom = lp.load_custom_categories(str(f))
        assert "INTERNAL-PROPRIETARY" in custom["permissive"]
        # 同名 id 迁移：MIT 从 permissive 挪到 unknown 之外的自定义类别不受支持，
        # 但扩充类别的 id 必须从其他类别移除
        assert lp.classify_license("internal-proprietary", custom) == "permissive"

    def test_yaml_requires_pyyaml(self, tmp_path):
        pytest.importorskip("yaml", reason="未安装 pyyaml 时跳过 YAML 路径")
        f = tmp_path / "cats.yaml"
        f.write_text("weak_copyleft:\n  - CUSTOM-WEAK\n", encoding="utf-8")
        custom = lp.load_custom_categories(str(f))
        assert "CUSTOM-WEAK" in custom["weak_copyleft"]

    def test_unknown_category_rejected(self, tmp_path):
        f = tmp_path / "bad.json"
        f.write_text(json.dumps({"public_domain": ["X"]}), encoding="utf-8")
        with pytest.raises(ValueError):
            lp.load_custom_categories(str(f))

    def test_missing_file(self, tmp_path):
        with pytest.raises(ValueError):
            lp.load_custom_categories(str(tmp_path / "nope.json"))
