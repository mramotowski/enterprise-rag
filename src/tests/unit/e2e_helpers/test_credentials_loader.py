#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Copyright (C) 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

"""
Unit tests for the e2e credential loading (tests/e2e/helpers).

With secrets_backend: local the helpers read default_credentials.txt; with
secrets_backend: openbao no file is written and they read the Secret
keycloak/erag-credentials (the ESO projection of OpenBao). No cluster is
contacted: kr8s is replaced by a fake, and the client libraries the helpers import
(kr8s, mcp, httpx, requests) are stubbed when they are not installed.
"""

import base64
import importlib
import sys
import types

import pytest


def _stub(name, **attrs):
    module = types.ModuleType(name)
    module.__dict__.update(attrs)
    sys.modules[name] = module
    return module


def _ensure(name, factory):
    try:
        importlib.import_module(name)
    except ImportError:
        factory()


_ensure("requests", lambda: _stub("requests"))
_ensure("httpx", lambda: _stub("httpx", Auth=object, AsyncClient=object, Timeout=object))
_ensure("mcp", lambda: (_stub("mcp", ClientSession=object), _stub("mcp.client"),
                        _stub("mcp.client.sse", sse_client=None)))
_ensure("kr8s", lambda: (_stub("kr8s", ALL="all", get=None),
                         _stub("kr8s.objects", new_class=lambda *a, **k: object)))
sys.modules["kr8s"].objects = sys.modules["kr8s.objects"]

from tests.e2e.helpers import k8s_helper as k8s_module  # noqa: E402
from tests.e2e.helpers import keycloak_helper as kh  # noqa: E402
from tests.e2e.helpers.mcp_helper import McpHelper  # noqa: E402


def _b64(value):
    return base64.b64encode(value.encode()).decode()


class _FakeSecret:
    def __init__(self, name, namespace, data):
        self.name, self.namespace, self.raw = name, namespace, {"data": data}


class _FakeK8s:
    """K8sHelper stand-in: read_secret_data returns a value or raises."""

    def __init__(self, result=None, error=None):
        self.result, self.error, self.calls = result, error, []

    def read_secret_data(self, name, namespace):
        self.calls.append((namespace, name))
        if self.error:
            raise self.error
        return self.result


@pytest.fixture
def log_dir(tmp_path, monkeypatch):
    default = tmp_path / "default_credentials.txt"
    monkeypatch.setattr(kh, "DEFAULT_CREDENTIALS_PATH", str(default))
    monkeypatch.setattr(kh, "cfg", {})
    return tmp_path


def _write(path, text):
    path.write_text(text)
    return str(path)


def test_parse_credentials_file(tmp_path):
    path = _write(tmp_path / "c.txt", '# comment\n\nKEYCLOAK_ERAG_ADMIN_USERNAME=erag-admin\n'
                                      'KEYCLOAK_ERAG_ADMIN_PASSWORD="a=b"\nno separator\n')
    assert kh.parse_credentials_file(path) == {"KEYCLOAK_ERAG_ADMIN_USERNAME": "erag-admin",
                                               "KEYCLOAK_ERAG_ADMIN_PASSWORD": "a=b"}


def test_explicit_file_preferred_over_secret(log_dir):
    explicit = _write(log_dir / "explicit.txt", 'KEYCLOAK_ERAG_ADMIN_PASSWORD="from-file"\n')
    k8s = _FakeK8s(result={"KEYCLOAK_ERAG_ADMIN_PASSWORD": "from-secret"})
    assert kh.load_erag_credentials(explicit, k8s) == {"KEYCLOAK_ERAG_ADMIN_PASSWORD": "from-file"}
    assert k8s.calls == []


def test_missing_explicit_file_then_default_file(log_dir):
    _write(log_dir / "default_credentials.txt", 'KEYCLOAK_ERAG_ADMIN_PASSWORD="default"\n')
    k8s = _FakeK8s(result={"KEYCLOAK_ERAG_ADMIN_PASSWORD": "from-secret"})
    assert kh.load_erag_credentials(str(log_dir / "absent.txt"), k8s) == {"KEYCLOAK_ERAG_ADMIN_PASSWORD": "default"}
    assert k8s.calls == []


def test_no_file_reads_the_projected_secret(log_dir):
    k8s = _FakeK8s(result={"KEYCLOAK_ERAG_ADMIN_PASSWORD": "from-secret"})
    assert kh.load_erag_credentials(str(log_dir / "absent.txt"), k8s) == {"KEYCLOAK_ERAG_ADMIN_PASSWORD": "from-secret"}
    assert k8s.calls == [("keycloak", "erag-credentials")]


def test_secret_namespace_from_config(log_dir):
    kh.cfg["keycloak_namespace"] = "kc"
    k8s = _FakeK8s(result={"MCP_CLIENT_ID": "mcp-client"})
    kh.load_erag_credentials(None, k8s)
    assert k8s.calls == [("kc", "erag-credentials")]


@pytest.mark.parametrize("k8s, reason", [
    (_FakeK8s(result=None), "it does not exist"),
    (_FakeK8s(result={}), "it holds no keys"),
    (_FakeK8s(error=ConnectionError("cluster unreachable")),
     "reading it failed: ConnectionError: cluster unreachable"),
    (None, "no Kubernetes helper to read it"),
])
def test_neither_source_raises_naming_both(log_dir, k8s, reason):
    explicit = str(log_dir / "absent.txt")
    with pytest.raises(kh.CredentialsNotFound) as raised:
        kh.load_erag_credentials(explicit, k8s)
    message = str(raised.value)
    assert explicit in message and kh.DEFAULT_CREDENTIALS_PATH in message
    assert "keycloak/erag-credentials" in message
    assert f"({reason})" in message


def test_read_secret_data_decodes(monkeypatch):
    calls = []

    def fake_get(kind, namespace=None, field_selector=None, **kwargs):
        calls.append((kind, namespace, field_selector))
        if field_selector == "metadata.name=erag-credentials":
            return [_FakeSecret("erag-credentials", namespace,
                                {"MCP_CLIENT_ID": _b64("mcp-client"), "MCP_CLIENT_SECRET": _b64("s3cr=t")})]
        return []

    monkeypatch.setattr(k8s_module.kr8s, "get", fake_get)
    helper = k8s_module.K8sHelper()
    assert helper.read_secret_data("erag-credentials", "keycloak") == {"MCP_CLIENT_ID": "mcp-client",
                                                                      "MCP_CLIENT_SECRET": "s3cr=t"}
    assert calls == [("secrets", "keycloak", "metadata.name=erag-credentials")]
    assert helper.read_secret_data("other", "keycloak") is None


def test_mcp_credentials_mapping_from_file(log_dir):
    path = _write(log_dir / "c.txt", 'MCP_CLIENT_ID=mcp-client\nMCP_CLIENT_SECRET="file-secret"\n')
    assert McpHelper._load_mcp_credentials(None, path, _FakeK8s()) == {"client_id": "mcp-client",
                                                                         "client_secret": "file-secret"}


def test_mcp_credentials_mapping_from_secret(log_dir):
    k8s = _FakeK8s(result={"MCP_CLIENT_ID": "mcp-client", "MCP_CLIENT_SECRET": "secret-value",
                           "KEYCLOAK_ERAG_ADMIN_PASSWORD": "ignored"})
    assert McpHelper._load_mcp_credentials(None, None, k8s) == {"client_id": "mcp-client",
                                                                  "client_secret": "secret-value"}


def test_mcp_credentials_missing_keys_are_empty(log_dir):
    k8s = _FakeK8s(result={"KEYCLOAK_ERAG_ADMIN_PASSWORD": "x"})
    assert McpHelper._load_mcp_credentials(None, None, k8s) == {"client_id": "", "client_secret": ""}
