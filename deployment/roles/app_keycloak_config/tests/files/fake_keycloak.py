#!/usr/bin/env python3
# Copyright (C) 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0
"""Test harness for test_configurator.yaml: runs files/keycloak_configurator_job.sh
against a fake Keycloak admin REST API and a kubectl stub, without a cluster.

    fake_keycloak.py run <work-dir> <script> <case.json>

case.json: {"name": <case>, "env": {VAR: value}, "fail_secret_client": <clientId>,
"kubectl_seed": {<ns>/<name>: {KEY: value}}, "kc_seed": <keycloak state>}.
The Keycloak state persists in <work-dir>/kc-state.json between runs (a re-run
sees the users and clients of the previous one) unless kc_seed replaces it; the
kubectl stub keeps its Secrets in <work-dir>/kubectl-state.json. Per case it
writes <work-dir>/<case>/{trace.jsonl (one request per line: method, path,
body), kubectl.jsonl (one kubectl argv per line), out.log, result.json
({rc})}.

The fake Keycloak models what the script relies on: realms with their password
policy (length, digits, upperCase, lowerCase, specialChars are enforced on user
creation, 400 otherwise), clients (409 on a duplicate clientId; a confidential
client gets a secret derived from its clientId unless the representation sets
"secret"; a service-account user only when created with serviceAccountsEnabled,
as Keycloak does), users (409 on a duplicate username; exact search) and the
client-secret endpoint. Any other GET returns [] and any other write succeeds.
fail_secret_client makes every update that sets that client's secret fail (500).
"""

import hashlib
import json
import os
import re
import subprocess
import sys
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

KUBECTL_STUB = r'''#!@PYTHON@
import base64, json, os, sys
import yaml
state_path = os.environ["FAKE_KUBECTL_STATE"]
with open(os.environ["FAKE_KUBECTL_LOG"], "a", encoding="utf-8") as log:
    log.write(json.dumps(sys.argv[1:]) + "\n")
state = json.load(open(state_path)) if os.path.exists(state_path) else {}
args = sys.argv[1:]
if args[:2] == ["get", "secret"]:
    name = args[2]
    ns = args[args.index("-n") + 1]
    secret = state.get(ns + "/" + name)
    if secret is None:
        sys.stderr.write("Error from server (NotFound)\n")
        sys.exit(1)
    for a in args:
        if a.startswith("jsonpath={.data."):
            key = a[len("jsonpath={.data."):-1]
            sys.stdout.write(secret.get(key, ""))
    sys.exit(0)
if args[:2] == ["apply", "-f"]:
    doc = yaml.safe_load(sys.stdin.read())
    state[doc["metadata"]["namespace"] + "/" + doc["metadata"]["name"]] = {
        k: str(v) for k, v in (doc.get("data") or {}).items()}
    json.dump(state, open(state_path, "w"))
    sys.exit(0)
sys.stderr.write("kubectl stub: unsupported %s\n" % args)
sys.exit(2)
'''


def policy_errors(policy, password):
    errors = []
    checks = {
        "length": lambda n: len(password) >= n,
        "digits": lambda n: len(re.findall(r"[0-9]", password)) >= n,
        "upperCase": lambda n: len(re.findall(r"[A-Z]", password)) >= n,
        "lowerCase": lambda n: len(re.findall(r"[a-z]", password)) >= n,
        "specialChars": lambda n: len(re.findall(r"[^A-Za-z0-9]", password)) >= n,
    }
    for name, arg in re.findall(r"(\w+)\((\d+)\)", policy or ""):
        if name in checks and not checks[name](int(arg)):
            errors.append(name)
    return errors


class FakeKeycloak:
    def __init__(self, state, trace_path, fail_secret_client):
        self.state = state
        self.trace_path = trace_path
        self.fail_secret_client = fail_secret_client
        self.lock = threading.Lock()

    def realm(self, name):
        return self.state["realms"].setdefault(name, {"policy": "", "clients": {}, "users": {}})

    def handle(self, method, raw_path, body):
        url = urlparse(raw_path)
        path, query = url.path, parse_qs(url.query)
        with open(self.trace_path, "a", encoding="utf-8") as trace:
            trace.write(json.dumps({"method": method, "path": raw_path, "body": body}) + "\n")
        data = None
        if body:
            try:
                data = json.loads(body)
            except ValueError:
                data = None
        if path == "/realms/master/protocol/openid-connect/token":
            return 200, {"access_token": "test-token"}
        if method == "GET" and path == "/realms/master":
            return 200, {"realm": "master"}
        m = re.fullmatch(r"/admin/realms", path)
        if m and method == "POST":
            if data["realm"] in self.state["realms"]:
                return 409, {}
            self.state["realms"][data["realm"]] = {"policy": data.get("passwordPolicy", ""),
                                                   "clients": {}, "users": {}}
            return 201, None
        m = re.fullmatch(r"/admin/realms/([^/]+)/clients", path)
        if m:
            realm = self.realm(m.group(1))
            if method == "GET":
                return 200, [{"id": c["id"], "clientId": cid} for cid, c in realm["clients"].items()]
            if method == "POST":
                if data["clientId"] in realm["clients"]:
                    return 409, {}
                client = dict(data, id=str(uuid.uuid4()))
                if not data.get("publicClient", True) and "secret" not in data:
                    client["secret"] = hashlib.sha256(data["clientId"].encode()).hexdigest()[:32]
                client["sa_user"] = bool(data.get("serviceAccountsEnabled"))
                realm["clients"][data["clientId"]] = client
                return 201, None
        m = re.fullmatch(r"/admin/realms/([^/]+)/clients/([^/]+)(/[a-z-]+)?", path)
        if m:
            realm = self.realm(m.group(1))
            found = [(cid, c) for cid, c in realm["clients"].items() if c["id"] == m.group(2)]
            if not found:
                return 404, {}
            cid, client = found[0]
            sub = m.group(3)
            if sub is None and method == "PUT":
                if data and "secret" in data and cid == self.fail_secret_client:
                    return 500, {}
                client.update({k: v for k, v in (data or {}).items() if k != "id"})
                return 204, None
            if sub is None and method == "DELETE":
                del realm["clients"][cid]
                return 204, None
            if sub == "/client-secret" and method == "GET":
                return 200, {"type": "secret", "value": client.get("secret", "")}
            if sub == "/service-account-user" and method == "GET":
                if client.get("sa_user"):
                    return 200, {"id": "sa-" + client["id"], "username": "service-account-" + cid}
                return 404, {}
        m = re.fullmatch(r"/admin/realms/([^/]+)/users", path)
        if m:
            realm = self.realm(m.group(1))
            if method == "GET":
                name = (query.get("username") or [""])[0]
                user = realm["users"].get(name)
                return 200, ([{"id": user["id"], "username": name}] if user else [])
            if method == "POST":
                if data["username"] in realm["users"]:
                    return 409, {}
                cred = (data.get("credentials") or [{}])[0]
                if policy_errors(realm["policy"], cred.get("value", "")):
                    return 400, {"error": "invalidPasswordMinLengthMessage"}
                realm["users"][data["username"]] = {"id": str(uuid.uuid4()), "password": cred.get("value"),
                                                    "temporary": cred.get("temporary")}
                return 201, None
        if method == "GET":
            return 200, []
        return (201 if method == "POST" else 204), None


def run(work, script, case_path):
    with open(case_path, encoding="utf-8") as handle:
        case = json.load(handle)
    case_dir = os.path.join(work, case["name"])
    os.makedirs(case_dir, exist_ok=True)
    kc_state_path = os.path.join(work, "kc-state.json")
    if "kc_seed" in case:
        state = case["kc_seed"]
    elif os.path.exists(kc_state_path):
        with open(kc_state_path, encoding="utf-8") as handle:
            state = json.load(handle)
    else:
        state = {"realms": {}}
    kubectl_state = os.path.join(work, "kubectl-state.json")
    if "kubectl_seed" in case:
        with open(kubectl_state, "w", encoding="utf-8") as handle:
            import base64

            json.dump({ref: {k: base64.b64encode(v.encode()).decode() for k, v in data.items()}
                       for ref, data in case["kubectl_seed"].items()}, handle)
    bin_dir = os.path.join(work, "bin")
    os.makedirs(bin_dir, exist_ok=True)
    stub = os.path.join(bin_dir, "kubectl")
    with open(stub, "w", encoding="utf-8") as handle:
        handle.write(KUBECTL_STUB.replace("@PYTHON@", sys.executable))
    os.chmod(stub, 0o755)

    fake = FakeKeycloak(state, os.path.join(case_dir, "trace.jsonl"), case.get("fail_secret_client"))

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def _serve(self):
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length).decode() if length else ""
            with fake.lock:
                code, payload = fake.handle(self.command, self.path, body)
            out = b"" if payload is None else json.dumps(payload).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(out)))
            self.end_headers()
            self.wfile.write(out)

        do_GET = do_POST = do_PUT = do_DELETE = _serve

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_address[1]}"
    env = {k: v for k, v in os.environ.items() if k in ("HOME", "LANG", "LC_ALL", "TMPDIR")}
    env.update({
        "PATH": bin_dir + os.pathsep + os.environ["PATH"],
        "KEYCLOAK_URL": base,
        "FAKE_KUBECTL_STATE": kubectl_state,
        "FAKE_KUBECTL_LOG": os.path.join(case_dir, "kubectl.jsonl"),
    })
    env.update({k: v.replace("@BASE@", base) for k, v in case.get("env", {}).items()})
    open(env["FAKE_KUBECTL_LOG"], "a").close()
    with open(os.path.join(case_dir, "out.log"), "w", encoding="utf-8") as out:
        proc = subprocess.run(["bash", script], env=env, stdout=out, stderr=subprocess.STDOUT,
                              timeout=600, check=False)
    server.shutdown()
    with open(kc_state_path, "w", encoding="utf-8") as handle:
        json.dump(state, handle)
    with open(os.path.join(case_dir, "result.json"), "w", encoding="utf-8") as handle:
        json.dump({"rc": proc.returncode}, handle)
    print(json.dumps({"rc": proc.returncode}))


def main():
    cmd, args = sys.argv[1], sys.argv[2:]
    if cmd == "run":
        run(*args)
    else:
        sys.exit("unknown command " + cmd)


if __name__ == "__main__":
    main()
