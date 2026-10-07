#!/usr/bin/env python3
# Copyright (C) 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

"""
In-cluster Keycloak client secret drift check (projected Secrets; AD-3).

Run by the Job in templates/client-drift-job.yaml.j2 on validate: logs in to the
Keycloak admin API (realm master, admin-cli), reads the secret Keycloak holds for
each client erag manages and compares it, in the pod, with the value projected
from OpenBao. A secret regenerated in the Keycloak admin console breaks the
client silently while the projection stays synced; install re-applies the
OpenBao value. Every value comes only from the environment (secretKeyRef).

Environment:
  KEYCLOAK_URL                       Keycloak base URL (internal Service)
  KEYCLOAK_ADMIN_USER                admin user (keycloak_admin_user, as the configurator)
  KEYCLOAK_ADMIN_PASSWORD            admin password (secretKeyRef password)
  DRIFT_CLIENTS                      JSON list of {"client_id", "realm", "env"}:
                                     env names the variable with the projected value
  DRIFT_TIMEOUT                      seconds per HTTP request

Prints exactly one JSON line and exits 0, never a value or a hash of one:
  {"clients": {"mcp-client": "match", "grafana-oauth": "drift"}, "admin_login": true}
Per client: match, drift, no_projection (no projected value), not_in_keycloak
(no such client in the realm) or error (admin login or the API call failed).
"""

import hmac
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request


def http(open_url, base, method, path, timeout, token=None, form=None):
    """Returns (status, parsed JSON or None); status -1 when there was no HTTP answer."""
    headers = {"Accept": "application/json"}
    data = None
    if token:
        headers["Authorization"] = "Bearer " + token
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    req = urllib.request.Request(base + path, data=data, method=method, headers=headers)
    try:
        with open_url(req, timeout=timeout) as resp:
            status, body = resp.status, resp.read()
    except urllib.error.HTTPError as err:
        return err.code, None
    except Exception:  # noqa: BLE001 - any transport failure is "no answer"
        return -1, None
    try:
        return status, json.loads(body or b"null")
    except ValueError:
        return status, None


def admin_token(open_url, base, timeout):
    password = os.environ.get("KEYCLOAK_ADMIN_PASSWORD", "")
    user = os.environ.get("KEYCLOAK_ADMIN_USER", "")
    if not password:
        return None
    status, doc = http(open_url, base, "POST", "/realms/master/protocol/openid-connect/token", timeout, form={
        "grant_type": "password", "client_id": "admin-cli", "username": user, "password": password})
    token = doc.get("access_token") if status == 200 and isinstance(doc, dict) else None
    return token or None


def client_state(open_url, base, timeout, token, realm, client_id, projected):
    quoted_realm = urllib.parse.quote(realm, safe="")
    status, doc = http(open_url, base, "GET", "/admin/realms/%s/clients?clientId=%s" % (
        quoted_realm, urllib.parse.quote(client_id, safe="")), timeout, token=token)
    if status == 404:
        return "not_in_keycloak"  # the realm itself does not exist
    if status != 200 or not isinstance(doc, list):
        return "error"
    match = [c for c in doc if isinstance(c, dict) and c.get("clientId") == client_id and c.get("id")]
    if not match:
        return "not_in_keycloak"
    if len(match) > 1:
        return "error"
    status, doc = http(open_url, base, "GET", "/admin/realms/%s/clients/%s/client-secret" % (
        quoted_realm, urllib.parse.quote(match[0]["id"], safe="")), timeout, token=token)
    if status != 200 or not isinstance(doc, dict):
        return "error"
    current = doc.get("value") or ""
    if not isinstance(current, str):
        return "error"
    same = hmac.compare_digest(current.encode(), projected.encode())
    return "match" if same else "drift"


def main():
    clients = json.loads(os.environ.get("DRIFT_CLIENTS", "[]"))
    timeout = max(1, int(os.environ.get("DRIFT_TIMEOUT", "15")))
    base = os.environ["KEYCLOAK_URL"].rstrip("/")
    result = {"clients": {}, "admin_login": False}
    projected = {}
    for c in clients:
        value = os.environ.get(str(c["env"]), "")
        if value:
            projected[str(c["client_id"])] = value
        else:
            result["clients"][str(c["client_id"])] = "no_projection"

    open_url = urllib.request.build_opener(urllib.request.ProxyHandler({})).open
    token = admin_token(open_url, base, timeout)
    result["admin_login"] = token is not None
    for c in clients:
        client_id = str(c["client_id"])
        if client_id not in projected:
            continue
        if token is None:
            result["clients"][client_id] = "error"
            continue
        try:
            state = client_state(open_url, base, timeout, token, str(c["realm"]), client_id, projected[client_id])
        except Exception:  # noqa: BLE001 - one client's failure is reported, not raised
            state = "error"
        result["clients"][client_id] = state
    return result


if __name__ == "__main__":
    try:
        OUT = main()
    except Exception:  # noqa: BLE001 - report, never a traceback that could echo input
        OUT = {"clients": {}, "admin_login": False, "error": True}
    sys.stdout.write(json.dumps(OUT) + "\n")
    sys.exit(0)
