#!/usr/bin/env python3
"""测试共享 mock（FakeResponse / CapturingHttpClient / license fetcher 系列）。

收敛自 test_g1/test_g2/test_g3 的重复定义；全部离线，不发起真实网络请求。
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))


class FakeResponse:
    """mock httpx.Response：仅暴露 .json()。"""

    def __init__(self, payload):
        self._payload = payload

    def json(self):
        return self._payload


class CapturingHttpClient:
    """捕获 OSV querybatch 请求体的假 HTTP 客户端（离线，返回全空结果）。"""

    def __init__(self):
        self.calls = []

    def post(self, url, json=None, headers=None):
        self.calls.append(json)
        n = len(json["queries"])
        return FakeResponse({"results": [{} for _ in range(n)]})


class MapLicenseFetcher:
    """license 查询 mock：按包名返回固定 license，未登记的返回空。"""

    def __init__(self, license_map):
        self._license_map = license_map

    def fetch_many(self, items):
        return {
            (name, eco): {"description": "", "license": self._license_map.get(name, "")}
            for name, eco in items
        }

    def fetch(self, name, eco):
        return {"description": "", "license": self._license_map.get(name, "")}


class NullLicenseFetcher:
    """license 查询 mock：一律返回空（generate_report 内部消费，不影响断言）。"""

    def fetch_many(self, items):
        return {(name, eco): {} for name, eco in items}

    def fetch(self, name, eco):
        return {}


class FailingLicenseFetcher:
    """license 查询 mock：fetch_many/fetch 均抛异常（模拟环境故障）。"""

    def fetch_many(self, items):
        raise RuntimeError("registry unreachable")

    def fetch(self, name, eco):
        raise RuntimeError("registry unreachable")
