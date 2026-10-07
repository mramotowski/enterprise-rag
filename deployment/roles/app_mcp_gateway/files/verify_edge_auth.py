#!/usr/bin/env python3
# Copyright (C) 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

"""
In-cluster MCP edge authentication check (projected Secrets; AD-3).

Run by the Job in templates/edge-auth-job.yaml.j2: mints an agent token with
the client_credentials grant, the way an agent integration does, then presents
it to the MCP route until the edge stops answering 401/403. The client id and
secret come only from the environment (secretKeyRef), never from argv.

Environment:
  MCP_CLIENT_ID, MCP_CLIENT_SECRET   agent client credentials (secretKeyRef)
  MCP_TOKEN_URL                      <issuer>/protocol/openid-connect/token
  MCP_RESOURCE_URL                   URL probed with the token
  MCP_EDGE_AUTH_RETRIES              retries while the edge answers 401/403
  MCP_EDGE_AUTH_DELAY                seconds between attempts

Prints exactly one JSON line and exits 0, never the token or the secret:
  {"credentials": true, "token": true, "token_http": 200, "edge_http": 404, "attempts": 3}
HTTP -1 means the endpoint did not answer (DNS, connect, TLS or timeout).
"""

import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

REJECTED = (401, 403)


def opener():
    # The edge serves a self-signed certificate by default and the request stays
    # inside the cluster: what is under test is the JWT verdict, not the chain.
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return urllib.request.build_opener(
        urllib.request.ProxyHandler({}), urllib.request.HTTPSHandler(context=context)
    )


def request(open_url, req, timeout):
    """Returns (status, body); status -1 when there was no HTTP answer."""
    try:
        with open_url(req, timeout=timeout) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as err:
        return err.code, b""
    except Exception:  # noqa: BLE001 - any transport failure is "unreachable"
        return -1, b""


def main():
    result = {"credentials": False, "token": False, "token_http": -1, "edge_http": -1, "attempts": 0}
    client_id = os.environ.get("MCP_CLIENT_ID", "")
    client_secret = os.environ.get("MCP_CLIENT_SECRET", "")
    if not client_id or not client_secret:
        return result
    result["credentials"] = True

    open_url = opener().open
    form = urllib.parse.urlencode(
        {"grant_type": "client_credentials", "client_id": client_id, "client_secret": client_secret}
    ).encode()
    token_req = urllib.request.Request(
        os.environ["MCP_TOKEN_URL"],
        data=form,
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    status, body = request(open_url, token_req, 15)
    result["token_http"] = status
    token = None
    if status == 200:
        try:
            token = json.loads(body).get("access_token")
        except ValueError:
            token = None
    if not token:
        return result
    result["token"] = True

    retries = max(0, int(os.environ.get("MCP_EDGE_AUTH_RETRIES", "10")))
    delay = max(0, int(os.environ.get("MCP_EDGE_AUTH_DELAY", "15")))
    for attempt in range(1, retries + 2):
        edge_req = urllib.request.Request(
            os.environ["MCP_RESOURCE_URL"], method="GET", headers={"Authorization": "Bearer " + token}
        )
        result["attempts"] = attempt
        # 404 is the success signal: the JWT filter admitted the request and the
        # service has no handler on the bare prefix. 401/403 is Envoy rejecting it.
        result["edge_http"] = request(open_url, edge_req, 10)[0]
        if result["edge_http"] not in REJECTED or attempt > retries:
            break
        time.sleep(delay)
    return result


if __name__ == "__main__":
    try:
        OUT = main()
    except Exception:  # noqa: BLE001 - report, never a traceback that could echo input
        OUT = {"credentials": False, "token": False, "token_http": -1, "edge_http": -1, "attempts": 0, "error": True}
    sys.stdout.write(json.dumps(OUT) + "\n")
    sys.exit(0)
