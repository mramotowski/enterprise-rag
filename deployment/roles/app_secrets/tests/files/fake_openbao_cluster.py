#!/usr/bin/env python3
# Copyright (C) 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0
"""Test harness for the app_secrets openbao adapter (tests only, needs Docker).

Plays the cluster side of tests/test_openbao_adapter.yaml without a cluster:

  start <dir>        OpenBao 2.7.0 in dev-tls mode (Docker, host network,
                     127.0.0.1 only) set up like enterprise-ai-solutions
                     roles/openbao/files/bootstrap.sh does for layer erag (KV v2
                     mount, auth/kubernetes, eso-erag and erag-secrets-worker
                     policies and roles), plus a fake Kubernetes TokenReview API
                     that OpenBao's Kubernetes auth calls. Writes <dir>/env.json.
  stop <dir>         removes the container and the TokenReview server.
  hook <state> <key> FAKE_K8S_ON_APPLY of the fake kubernetes.core.k8s:
                       Job            runs the Job's container in Docker exactly
                                      as specified (command, args, env values,
                                      ConfigMap and emptyDir volumes, projected
                                      token minted for its audience), stores the
                                      log and the Job status;
                       ExternalSecret plays ESO: reads each remoteRef from
                                      OpenBao, renders target.template and writes
                                      the Secret and the Ready condition. An
                                      existing Secret is adopted: its labels and
                                      annotations stay, ESO's owner reference
                                      and the data replace the rest.
                     A Job whose container runs python3 (the importer) runs
                     on this host instead (no python image in Docker here):
                     the volume mount paths in its env are remapped to temp
                     dirs, KUBE_API points to a fake Kubernetes API over TLS
                     (the OpenBao dev certificate) that serves and merge-
                     patches the Secrets of the state file and enforces the
                     Roles/RoleBindings of the Job's ServiceAccount
                     (resourceNames included). Every API request is recorded in
                     "FakeKubeApi//requests", and the Roles/RoleBindings present
                     at run time in the run archive (rbac).
                     With FAKE_K8S_POLLS=<n> the final Job status / Ready
                     condition shows only after n reads (fake k8s_info); with
                     FAKE_ESO_FAIL set, ESO reports Ready=False.
  root <dir> <args>  one bao command with the dev root token (test setup only).
  verify-nkey <dir> <kv path>
                     prints "ok" when seed and public_key form one NKey pair.
  check <dir> <kv path> <key> <regex>
                     prints "ok" when the value matches the regex.
  secret-equals <dir> <state> <ns>/<name> <secret key> <expected>
                     prints "ok" when the Secret key equals <expected>, where
                     <<<kv path>#<key>>> in <expected> stands for that KV value.
  put-random <dir> <kv path> <key>
                     writes a random test value (on stdin, never in argv).
  test-registry <src> <out>
                     the registry plus test templates and test-only credentials.
  joblogs <state> <out>
                     writes every stored worker Job log line to <out>.
  values <dir> <out> writes every KV value under the mount to <out>, one per
                     line (for the no-value-in-output grep); prints the count.
  count <dir> <prefix>
                     prints the number of entries (metadata, so also those
                     without a live version) under <prefix>, recursively.
  seed-legacy <state> <spec.json> <credentials file> <values out>
                     the Secrets of a local-mode env (migration tests): the
                     legacy Secret keys of spec.json get the value of their
                     file_var line in the credentials file (written by the local
                     adapter), else a random one per credential key; markup,
                     Helm ownership and extra Secrets as the spec says. Every
                     value goes to <values out> (for the leak grep).
  secret-digests <state> <out.json>
                     {"<ns>/<name>#<key>": sha256} of every Secret key.
  helm-drop <state> <ns>/<name> ...
                     plays a Helm upgrade that no longer templates these
                     Secrets: deleted unless annotated helm.sh/resource-policy:
                     keep (Helm reads the live object); prints kept/deleted.
  helm-upgrade <state> <ns> <release> <status>
                     a new revision of the release with that status (no value).
  fake-helm <helm args>
                     "helm list" / "helm history" from "FakeHelm//releases" of
                     FAKE_K8S_STATE (fake helm on PATH in the tests).
  rbac-allows <state> <job name> <ns> <name> <verb>
                     prints allow/deny for the importer ServiceAccount under
                     the Roles archived for that run.

Values are only ever compared here; this script prints "ok"/"mismatch", never
a value ("values" writes them to a file for grep -F -f).
The dev root token lives only in <dir>/env.json (a throwaway test instance).
"""

import base64
import hashlib
import io
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

IMAGE = os.environ.get("FAKE_OPENBAO_IMAGE", "quay.io/openbao/openbao:2.7.0")
MOUNT = "intel-ai"
LAYER = "erag"
WORKER_NS = "erag-secrets"
WORKER_SA = "erag-secrets-worker"
ESO_NS = "external-secrets"
ESO_SA = "external-secrets"
AUDIENCE = "vault"


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def load_env(directory):
    with open(os.path.join(directory, "env.json"), encoding="utf-8") as handle:
        return json.load(handle)


def bao(env, args, stdin=None, check=True):
    cmd = ["docker", "exec", "-i", "-e", "BAO_ADDR=" + env["addr"], "-e", "BAO_CACERT=/tmp/tls/vault-ca.pem",
           "-e", "BAO_TOKEN=" + env["root"], env["container"], "bao"] + args
    run = subprocess.run(cmd, input=stdin, capture_output=True, text=True, check=False)
    if check and run.returncode != 0:
        raise RuntimeError("bao %s failed: %s" % (" ".join(args[:3]), run.stderr.strip()[-500:]))
    return run


def kv_get(env, path):
    """KV v2 data of <path> (relative to the mount) or None."""
    run = bao(env, ["kv", "get", "-format=json", "-mount=" + MOUNT, path], check=False)
    if run.returncode != 0:
        return None
    return json.loads(run.stdout)["data"]["data"]


def kv_get_version(env, path, version=None):
    """KV v2 data of <path> at <version> (latest when None) or None."""
    args = ["kv", "get", "-format=json", "-mount=" + MOUNT]
    if version:
        args.append("-version=%s" % version)
    run = bao(env, args + [path], check=False)
    if run.returncode != 0:
        return None
    return (json.loads(run.stdout).get("data") or {}).get("data")


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def mint_jwt(namespace, sa_name, audience):
    """A ServiceAccount-token-shaped JWT (the fake TokenReview vouches for it)."""
    now = int(time.time())
    claims = {"iss": "https://kubernetes.default.svc", "sub": "system:serviceaccount:%s:%s" % (namespace, sa_name),
              "aud": [audience], "iat": now, "nbf": now, "exp": now + 600,
              "kubernetes.io": {"namespace": namespace, "serviceaccount": {"name": sa_name, "uid": "uid-" + sa_name}}}
    header = {"alg": "RS256", "kid": "fake"}
    return "%s.%s.%s" % (b64url(json.dumps(header).encode()), b64url(json.dumps(claims).encode()),
                         b64url(secrets.token_bytes(32)))


# --- fake TokenReview API ------------------------------------------------------------


def serve_tokenreview(port, ready_file):
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802 (http.server API)
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
            token = body.get("spec", {}).get("token", "")
            requested = body.get("spec", {}).get("audiences") or []
            status = {"authenticated": False}
            try:
                claims = json.loads(base64.urlsafe_b64decode(token.split(".")[1] + "=="))
                sub = claims["sub"].split(":")
                if set(requested) & set(claims.get("aud", [])) and claims["exp"] > time.time():
                    status = {"authenticated": True, "audiences": sorted(set(requested) & set(claims["aud"])),
                              "user": {"username": claims["sub"], "uid": "uid-" + sub[3],
                                       "groups": ["system:serviceaccounts", "system:serviceaccounts:" + sub[2]]}}
            except (IndexError, KeyError, ValueError):
                pass
            data = json.dumps({"apiVersion": "authentication.k8s.io/v1", "kind": "TokenReview",
                               "status": status}).encode()
            self.send_response(201)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", port), Handler)
    with open(ready_file, "w", encoding="utf-8") as handle:
        handle.write("ready")
    server.serve_forever()


# --- start / stop --------------------------------------------------------------------


def start(directory):
    os.makedirs(directory, exist_ok=True)
    port, tr_port = free_port(), free_port()
    root = secrets.token_hex(16)
    suffix = secrets.token_hex(4)
    container = "app-secrets-test-openbao-" + suffix
    ready = os.path.join(directory, "tokenreview.ready")
    child = subprocess.Popen([sys.executable, os.path.abspath(__file__), "serve-tokenreview", str(tr_port), ready],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    env = {"container": container, "port": port, "addr": "https://127.0.0.1:%d" % port, "root": root,
           "tokenreview_pid": child.pid, "tokenreview_port": tr_port, "mount": MOUNT,
           "ca": os.path.join(directory, "ca.crt")}
    with open(os.path.join(directory, "env.json"), "w", encoding="utf-8") as handle:
        json.dump(env, handle)
    subprocess.run(["docker", "run", "-d", "--rm", "--name", container, "--network", "host",
                    "-e", "BAO_DEV_ROOT_TOKEN_ID=" + root, "--entrypoint", "sh", IMAGE, "-c",
                    "mkdir -p /tmp/tls && exec bao server -dev -dev-tls -dev-tls-cert-dir=/tmp/tls "
                    "-dev-listen-address=127.0.0.1:%d" % port],
                   check=True, capture_output=True)
    for _ in range(100):
        if os.path.exists(ready) and bao(env, ["status"], check=False).returncode == 0:
            break
        time.sleep(0.2)
    else:
        raise RuntimeError("OpenBao test container did not start")
    # The CA, and the dev server certificate (127.0.0.1) that also serves the
    # fake Kubernetes API of host-run Jobs.
    tls = subprocess.run(["docker", "exec", container, "tar", "-C", "/tmp/tls", "-cf", "-", "vault-ca.pem",
                          "vault-cert.pem", "vault-key.pem"], check=True, capture_output=True).stdout
    with tarfile.open(fileobj=io.BytesIO(tls)) as archive:
        pem = {m.name: archive.extractfile(m).read().decode() for m in archive.getmembers() if m.isfile()}
    for name, path in (("vault-ca.pem", env["ca"]), ("vault-cert.pem", os.path.join(directory, "vault-cert.pem")),
                       ("vault-key.pem", os.path.join(directory, "vault-key.pem"))):
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(pem[name])
        os.chmod(path, 0o600)
    # Mirror of bootstrap.sh (layer erag): mount, auth, policies, roles.
    bao(env, ["secrets", "enable", "-path=" + MOUNT, "-version=2", "kv"])
    bao(env, ["auth", "enable", "kubernetes"])
    bao(env, ["write", "auth/kubernetes/config", "kubernetes_host=http://127.0.0.1:%d" % tr_port,
              "kubernetes_ca_cert=@/tmp/tls/vault-ca.pem", "disable_local_ca_jwt=true",
              "token_reviewer_jwt=" + mint_jwt("kube-system", "token-reviewer", "https://kubernetes.default.svc")])
    cid = os.environ.get("FAKE_OPENBAO_CLUSTER_ID", "t1")
    bao(env, ["policy", "write", "eso-" + LAYER, "-"],
        stdin='path "%s/data/%s/%s/*" {\n  capabilities = ["read"]\n}\n' % (MOUNT, cid, LAYER))
    bao(env, ["write", "auth/kubernetes/role/eso-" + LAYER, "bound_service_account_names=" + ESO_SA,
              "bound_service_account_namespaces=" + ESO_NS, "token_policies=eso-" + LAYER, "audience=" + AUDIENCE])
    bao(env, ["policy", "write", LAYER + "-secrets-worker", "-"],
        stdin=('path "%s/data/%s/%s/*" {\n  capabilities = ["create", "update", "read", "delete"]\n}\n'
               'path "%s/metadata/%s/%s/*" {\n  capabilities = ["read", "list", "delete"]\n}\n')
        % (MOUNT, cid, LAYER, MOUNT, cid, LAYER))
    bao(env, ["write", "auth/kubernetes/role/%s-secrets-worker" % LAYER, "bound_service_account_names=" + WORKER_SA,
              "bound_service_account_namespaces=" + WORKER_NS, "token_policies=%s-secrets-worker" % LAYER,
              "audience=" + AUDIENCE])
    # bootstrap.sh: the importer (migration) gets the worker policy on data, minus delete.
    bao(env, ["policy", "write", LAYER + "-secrets-importer", "-"],
        stdin='path "%s/data/%s/%s/*" {\n  capabilities = ["create", "update", "read"]\n}\n' % (MOUNT, cid, LAYER))
    bao(env, ["write", "auth/kubernetes/role/%s-secrets-importer" % LAYER,
              "bound_service_account_names=%s-secrets-importer" % LAYER,
              "bound_service_account_namespaces=" + WORKER_NS, "token_policies=%s-secrets-importer" % LAYER,
              "audience=" + AUDIENCE])
    print(json.dumps({"addr": env["addr"], "ca": env["ca"], "container": container}))


def stop(directory):
    try:
        env = load_env(directory)
    except OSError:
        return
    subprocess.run(["docker", "rm", "-f", env["container"]], capture_output=True, check=False)
    try:
        os.killpg(env["tokenreview_pid"], 15)
    except OSError:
        pass


# --- the Job ---------------------------------------------------------------------------


def load_state(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def save_state(path, state):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump(state, handle, indent=1, sort_keys=True)
    os.replace(tmp, path)


def run_job(state_path, key):
    state = load_state(state_path)
    job = state[key]
    namespace = job["metadata"]["namespace"]
    pod = job["spec"]["template"]["spec"]
    (container,) = pod["containers"]
    if container["command"][0] == "python3":
        return run_host_job(state_path, key)
    volumes = {v["name"]: v for v in pod.get("volumes", [])}
    problems = []
    if pod.get("automountServiceAccountToken") is not False:
        problems.append("automountServiceAccountToken is not false")
    if any("secret" in v for v in volumes.values()):
        problems.append("a Secret volume is mounted")
    work = tempfile.mkdtemp(prefix="job-", dir=os.environ["FAKE_OPENBAO_DIR"])
    limit = (container.get("resources", {}).get("limits", {}) or {}).get("memory", "")
    cmd = ["docker", "run", "--rm", "--network", "host", "--read-only", "--cap-drop", "ALL",
           "--security-opt", "no-new-privileges"]
    if limit:
        # Same memory limit as the pod (Mi -> m), so the in-pod dev server fits.
        mem = limit.replace("Mi", "m").replace("Gi", "g")
        cmd += ["--memory", mem, "--memory-swap", mem]
    cmd += [
           "-u", "%s:%s" % (pod["securityContext"]["runAsUser"], pod["securityContext"]["runAsGroup"])]
    for item in container.get("env", []):
        if "value" not in item or "valueFrom" in item:
            problems.append("env %s is not a plain value" % item.get("name"))
            continue
        value = item["value"]
        if item["name"] == "BAO_ADDR" and os.environ.get("FAKE_OPENBAO_ADDR_OVERRIDE"):
            value = os.environ["FAKE_OPENBAO_ADDR_OVERRIDE"]
        cmd += ["-e", "%s=%s" % (item["name"], value)]
    for mount in container.get("volumeMounts", []):
        vol = volumes[mount["name"]]
        host = os.path.join(work, mount["name"])
        os.makedirs(host)
        if "configMap" in vol:
            cm = state.get("ConfigMap/%s/%s" % (namespace, vol["configMap"]["name"]))
            if cm is None:
                problems.append("ConfigMap %s missing" % vol["configMap"]["name"])
                continue
            items = vol["configMap"].get("items") or [{"key": k, "path": k} for k in cm.get("data", {})]
            for it in items:
                with open(os.path.join(host, it["path"]), "w", encoding="utf-8") as handle:
                    handle.write(cm["data"][it["key"]])
                os.chmod(os.path.join(host, it["path"]), 0o444)
            cmd += ["-v", "%s:%s:ro" % (host, mount["mountPath"])]
        elif "projected" in vol:
            for src in vol["projected"]["sources"]:
                token = src["serviceAccountToken"]
                with open(os.path.join(host, token["path"]), "w", encoding="utf-8") as handle:
                    handle.write(mint_jwt(namespace, pod["serviceAccountName"], token["audience"]))
                os.chmod(os.path.join(host, token["path"]), 0o444)
            cmd += ["-v", "%s:%s:ro" % (host, mount["mountPath"])]
        elif "emptyDir" in vol:
            cmd += ["--tmpfs", "%s:rw,size=16m,mode=0700,uid=%s,gid=%s" % (
                mount["mountPath"], pod["securityContext"]["runAsUser"], pod["securityContext"]["runAsGroup"])]
        else:
            problems.append("unsupported volume %s" % mount["name"])
    shim = os.environ.get("FAKE_OPENBAO_RACE_PATH")
    if shim:
        # Test-only race: the first metadata read of this path answers "not
        # found", so the worker's cas=0 write meets an existing entry.
        sdir = os.path.join(work, "shim")
        os.makedirs(sdir)
        with open(os.path.join(sdir, "bao"), "w", encoding="utf-8") as handle:
            handle.write('#!/bin/sh\ncase "$*" in *"metadata/%s"*) [ -e /work/.raced ] || { : > /work/.raced; '
                         'echo "No value found at x" >&2; exit 2; } ;; esac\nexec /usr/bin/bao "$@"\n' % shim)
        os.chmod(os.path.join(sdir, "bao"), 0o555)
        cmd += ["-v", "%s:/shim:ro" % sdir, "-e", "PATH=/shim:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"]
    cmd += ["--entrypoint", container["command"][0], container["image"]] + container["command"][1:] + container.get("args", [])
    if problems:
        lines, rc = ["fake-cluster: refused to run the Job: " + "; ".join(problems)], 1
    else:
        run = subprocess.run(cmd, capture_output=True, text=True, check=False)
        lines = (run.stdout + run.stderr).splitlines()
        rc = run.returncode
    state = load_state(state_path)
    final = {"succeeded" if rc == 0 else "failed": 1}
    polls = int(os.environ.get("FAKE_K8S_POLLS", "0"))
    if polls > 0:
        # k8s_info shows the final status only after <polls> reads (fake k8s_info).
        state[key]["_fake_polls_left"] = polls
        state[key]["_fake_final_status"] = final
    else:
        state[key].setdefault("status", {}).update(final)
    state["JobLog/%s/%s" % (namespace, job["metadata"]["name"])] = {"lines": lines, "rc": rc}
    # Archive the run: the adapter deletes old worker Jobs before each run.
    runs = state.setdefault("FakeJobRuns//all", {"names": [], "jobs": {}, "configmaps": {}})
    runs["names"].append(job["metadata"]["name"])
    runs["jobs"][job["metadata"]["name"]] = job
    runs["configmaps"][job["metadata"]["name"]] = state.get("ConfigMap/%s/%s" % (namespace, job["metadata"]["name"]))
    save_state(state_path, state)
    subprocess.run(["rm", "-rf", work], check=False)


# --- host-run (python) Jobs and the fake Kubernetes API ----------------------------------

KUBE_AUDIENCE = "https://kubernetes.default.svc"


def jwt_claims(token):
    try:
        return json.loads(base64.urlsafe_b64decode(token.split(".")[1] + "=="))
    except (IndexError, ValueError):
        return {}


def rbac_allows(state, sa_ns, sa_name, namespace, name, verb):
    """Role/RoleBinding check for one Secret (resourceNames honoured)."""
    for key, rb in state.items():
        if not key.startswith("RoleBinding/%s/" % namespace):
            continue
        if not any(sub.get("kind") == "ServiceAccount" and sub.get("name") == sa_name
                   and sub.get("namespace") == sa_ns for sub in rb.get("subjects", [])):
            continue
        ref = rb.get("roleRef", {})
        role = state.get("Role/%s/%s" % (namespace, ref.get("name"))) if ref.get("kind") == "Role" else None
        for rule in (role or {}).get("rules", []):
            if "" not in rule.get("apiGroups", []) or "secrets" not in rule.get("resources", []):
                continue
            if verb not in rule.get("verbs", []):
                continue
            names = rule.get("resourceNames")
            if names is None or name in names:
                return True
    return False


def serve_kube_api(state_path, cert_dir):
    """A TLS fake of the Secret endpoints of the Kubernetes API; returns (server, port)."""
    import ssl

    class Handler(BaseHTTPRequestHandler):
        def reply(self, code, body):
            data = json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def handle_secret(self, verb):
            parts = self.path.split("?")[0].strip("/").split("/")
            if len(parts) != 6 or parts[:3] != ["api", "v1", "namespaces"] or parts[4] != "secrets":
                return self.reply(404, {"kind": "Status", "message": "not found"})
            namespace, name = parts[3], parts[5]
            claims = jwt_claims(self.headers.get("Authorization", "").replace("Bearer ", "", 1))
            sub = (claims.get("sub") or "").split(":")
            state = load_state(state_path)
            allowed = (len(sub) == 4 and KUBE_AUDIENCE in claims.get("aud", []) and claims.get("exp", 0) > time.time()
                       and rbac_allows(state, sub[2], sub[3], namespace, name, verb))
            log = state.setdefault("FakeKubeApi//requests", {"items": []})["items"]
            log.append({"verb": verb, "namespace": namespace, "name": name, "allowed": allowed})
            denied = os.environ.get("FAKE_KUBE_DENY_PATCH", "")
            if allowed and verb == "patch" and denied == "%s/%s" % (namespace, name):
                allowed = log[-1]["allowed"] = False
                log[-1]["injected"] = True
            if not allowed:
                save_state(state_path, state)
                return self.reply(403, {"kind": "Status", "message": "secrets \"%s\" is forbidden" % name})
            obj = state.get("Secret/%s/%s" % (namespace, name))
            if obj is None:
                save_state(state_path, state)
                return self.reply(404, {"kind": "Status", "message": "secrets \"%s\" not found" % name})
            if verb == "patch":
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
                if self.headers.get("Content-Type") != "application/merge-patch+json" or set(body) - {"metadata"}:
                    log[-1]["rejected"] = True
                    save_state(state_path, state)
                    return self.reply(422, {"kind": "Status", "message": "only metadata merge patches (test)"})
                obj = merge_patch(obj, body)
                state["Secret/%s/%s" % (namespace, name)] = obj
            save_state(state_path, state)
            return self.reply(200, {k: v for k, v in obj.items() if not k.startswith("_fake")})

        def do_GET(self):  # noqa: N802 (http.server API)
            self.handle_secret("get")

        def do_PATCH(self):  # noqa: N802 (http.server API)
            self.handle_secret("patch")

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(os.path.join(cert_dir, "vault-cert.pem"), os.path.join(cert_dir, "vault-key.pem"))
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, server.server_address[1]


def merge_patch(base, patch):
    out = dict(base)
    for key, value in patch.items():
        if value is None:
            out.pop(key, None)
        elif isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = merge_patch(out[key], value)
        elif isinstance(value, dict):
            out[key] = merge_patch({}, value)
        else:
            out[key] = value
    return out


def remap_endpoints(work):
    """The rotator plan names in-cluster services; FAKE_ENDPOINTS (a JSON file
    {"<host>:<port>" | "<url>": "<host>:<port>" | "<url>"}) maps them to the test
    servers on this host. Only the copy the Job reads is changed."""
    path = os.environ.get("FAKE_ENDPOINTS")
    if not path:
        return
    with open(path, encoding="utf-8") as handle:
        endpoints = json.load(handle)
    for root, _dirs, files in os.walk(work):
        if "plan.json" not in files or "secrets_rotator.py" not in files:
            continue
        plan_path = os.path.join(root, "plan.json")
        with open(plan_path, encoding="utf-8") as handle:
            plan = json.load(handle)
        target = plan.get("target") or {}
        hostport = "%s:%s" % (target.get("host"), target.get("port"))
        if hostport in endpoints:
            target["host"], target["port"] = endpoints[hostport].rsplit(":", 1)
            target["port"] = int(target["port"])
        if plan.get("keycloak", {}).get("url") in endpoints:
            plan["keycloak"]["url"] = endpoints[plan["keycloak"]["url"]]
        os.chmod(plan_path, 0o644)
        with open(plan_path, "w", encoding="utf-8") as handle:
            json.dump(plan, handle)


def run_host_job(state_path, key):
    """The importer Job: its python3 command on this host (see the module doc)."""
    state = load_state(state_path)
    job = state[key]
    namespace = job["metadata"]["namespace"]
    pod = job["spec"]["template"]["spec"]
    (container,) = pod["containers"]
    volumes = {v["name"]: v for v in pod.get("volumes", [])}
    problems = []
    if pod.get("automountServiceAccountToken") is not False:
        problems.append("automountServiceAccountToken is not false")
    if any("secret" in v for v in volumes.values()):
        problems.append("a Secret volume is mounted")
    work = tempfile.mkdtemp(prefix="hostjob-", dir=os.environ["FAKE_OPENBAO_DIR"])
    remap = {}
    for mount in container.get("volumeMounts", []):
        vol = volumes[mount["name"]]
        host = os.path.join(work, mount["name"])
        os.makedirs(host)
        remap[mount["mountPath"]] = host
        if "configMap" in vol:
            cm = state.get("ConfigMap/%s/%s" % (namespace, vol["configMap"]["name"]))
            if cm is None:
                problems.append("ConfigMap %s missing" % vol["configMap"]["name"])
                continue
            items = vol["configMap"].get("items") or [{"key": k, "path": k} for k in cm.get("data", {})]
            for it in items:
                with open(os.path.join(host, it["path"]), "w", encoding="utf-8") as handle:
                    handle.write(cm["data"][it["key"]])
        elif "projected" in vol:
            for src in vol["projected"]["sources"]:
                token = src["serviceAccountToken"]
                with open(os.path.join(host, token["path"]), "w", encoding="utf-8") as handle:
                    handle.write(mint_jwt(namespace, pod["serviceAccountName"], token.get("audience", KUBE_AUDIENCE)))
        else:
            problems.append("unsupported volume %s" % mount["name"])
    remap_endpoints(work)
    server, port = serve_kube_api(state_path, os.environ["FAKE_OPENBAO_DIR"])
    env = {"PATH": "/usr/bin:/bin", "HOME": work}
    for item in container.get("env", []):
        if "value" not in item or "valueFrom" in item:
            problems.append("env %s is not a plain value" % item.get("name"))
            continue
        value = item["value"]
        for mount_path, host in remap.items():
            if value.startswith(mount_path + "/"):
                value = host + value[len(mount_path):]
        if item["name"] == "BAO_ADDR" and os.environ.get("FAKE_OPENBAO_ADDR_OVERRIDE"):
            value = os.environ["FAKE_OPENBAO_ADDR_OVERRIDE"]
        if item["name"] == "KUBE_API":
            value = "https://127.0.0.1:%d" % port
        env[item["name"]] = value
    argv = [sys.executable] + container["command"][1:] + container.get("args", [])
    argv = [next((h + a[len(m):] for m, h in remap.items() if a.startswith(m + "/")), a) for a in argv]
    rbac = {k: v for k, v in state.items() if k.split("/", 1)[0] in ("Role", "RoleBinding")}
    if problems:
        lines, rc = ["fake-cluster: refused to run the Job: " + "; ".join(problems)], 1
    else:
        run = subprocess.run(argv, capture_output=True, text=True, check=False, env=env, cwd=work, timeout=120)
        lines = (run.stdout + run.stderr).splitlines()
        rc = run.returncode
    server.shutdown()
    state = load_state(state_path)
    state[key].setdefault("status", {}).update({"succeeded" if rc == 0 else "failed": 1})
    state["JobLog/%s/%s" % (namespace, job["metadata"]["name"])] = {"lines": lines, "rc": rc}
    runs = state.setdefault("FakeJobRuns//all", {"names": [], "jobs": {}, "configmaps": {}})
    runs["names"].append(job["metadata"]["name"])
    runs["jobs"][job["metadata"]["name"]] = job
    runs["configmaps"][job["metadata"]["name"]] = state.get("ConfigMap/%s/%s" % (namespace, job["metadata"]["name"]))
    runs.setdefault("rbac", {})[job["metadata"]["name"]] = rbac
    save_state(state_path, state)
    shutil.rmtree(work, ignore_errors=True)


# --- ESO ---------------------------------------------------------------------------------

GO_ACTION = re.compile(r"\{\{ \.([A-Za-z0-9_]+) \}\}")


def run_eso(state_path, key):
    env = load_env(os.environ["FAKE_OPENBAO_DIR"])
    state = load_state(state_path)
    es = state[key]
    namespace = es["metadata"]["namespace"]
    spec = es["spec"]

    def condition(ok, reason, message):
        final = {"conditions": [{"type": "Ready", "status": "True" if ok else "False",
                                 "reason": reason, "message": message}],
                 "refreshTime": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
        polls = int(os.environ.get("FAKE_K8S_POLLS", "0"))
        state[key].pop("status", None)
        if polls > 0:
            state[key]["_fake_polls_left"] = polls
            state[key]["_fake_final_status"] = final
        else:
            state[key]["status"] = final
        save_state(state_path, state)

    if os.environ.get("FAKE_ESO_FAIL"):
        return condition(False, "SecretSyncedError", "injected failure (test)")

    store = state.get("ClusterSecretStore//" + spec["secretStoreRef"]["name"])
    if not store or not [c for c in store.get("status", {}).get("conditions", [])
                         if c["type"] == "Ready" and c["status"] == "True"]:
        return condition(False, "SecretSyncedError", "store not ready")
    ns_labels = (state.get("Namespace//" + namespace, {}).get("metadata", {}).get("labels") or {})
    for cond in store.get("spec", {}).get("conditions", []):
        wanted = cond.get("namespaceSelector", {}).get("matchLabels", {})
        if any(ns_labels.get(k) != v for k, v in wanted.items()):
            return condition(False, "SecretSyncedError", "namespace %s not allowed by the store" % namespace)
    if spec.get("dataFrom"):
        return condition(False, "SecretSyncedError", "dataFrom is refused by the admission policy (test)")
    # The platform admission policy: keys must be <cid>/<p> for p in the
    # namespace annotation secrets.ai-solutions/erag-paths, under erag/.
    ns_ann = (state.get("Namespace//" + namespace, {}).get("metadata", {}).get("annotations") or {})
    allowed = [p.strip() for p in ns_ann.get("secrets.ai-solutions/erag-paths", "").split(",") if p.strip()]
    cid = os.environ.get("FAKE_OPENBAO_CLUSTER_ID", "t1")
    for item in spec.get("data", []):
        if not any(p.startswith("erag/") and item["remoteRef"]["key"] == cid + "/" + p for p in allowed):
            return condition(False, "SecretSyncedError", "key %s denied by the admission policy (test)"
                             % item["remoteRef"]["key"])
    values = {}
    for item in spec.get("data", []):
        data = kv_get(env, item["remoteRef"]["key"])
        if data is None or item["remoteRef"]["property"] not in data:
            return condition(False, "SecretSyncedError", "cannot read %s" % item["remoteRef"]["key"])
        values[item["secretKey"]] = data[item["remoteRef"]["property"]]
    template = spec["target"]["template"]
    out = {}
    for skey, text in template.get("data", {}).items():
        rendered = GO_ACTION.sub(lambda m: values[m.group(1)], text)
        if "{{" in GO_ACTION.sub("", text):
            return condition(False, "SecretSyncedError", "unsupported template in " + skey)
        out[skey] = base64.b64encode(rendered.encode()).decode()
    skey = "Secret/%s/%s" % (namespace, spec["target"]["name"])
    old_meta = (state.get(skey) or {}).get("metadata", {})
    # creationPolicy Owner adopts an existing Secret: its labels and annotations stay.
    meta = {k: v for k, v in old_meta.items() if k in ("labels", "annotations")}
    meta.update({"name": spec["target"]["name"], "namespace": namespace,
                 "ownerReferences": [{"kind": "ExternalSecret", "name": es["metadata"]["name"]}]})
    state[skey] = {"apiVersion": "v1", "kind": "Secret", "type": template.get("type", "Opaque"),
                   "metadata": meta, "data": out}
    return condition(True, "SecretSynced", "secret synced")


# --- checks ------------------------------------------------------------------------------

B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"


def b32decode(text):
    bits, value, out = 0, 0, bytearray()
    for ch in text:
        value = (value << 5) | B32.index(ch)
        bits += 5
        if bits >= 8:
            bits -= 8
            out.append((value >> bits) & 0xFF)
    return bytes(out)


def crc16(data):
    crc = 0
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) if crc & 0x8000 else (crc << 1)
            crc &= 0xFFFF
    return crc


def verify_nkey(directory, path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    data = kv_get(load_env(directory), path) or {}
    seed, pub = data.get("seed", ""), data.get("public_key", "")
    raw_seed, raw_pub = b32decode(seed), b32decode(pub)
    ok = (len(seed) == 58 and seed.startswith("SU") and len(pub) == 56 and pub.startswith("U")
          and len(raw_seed) == 36 and len(raw_pub) == 35
          and raw_seed[:2] == bytes([0x95, 0x00]) and raw_pub[0] == 0xA0
          and crc16(raw_seed[:-2]) == int.from_bytes(raw_seed[-2:], "little")
          and crc16(raw_pub[:-2]) == int.from_bytes(raw_pub[-2:], "little"))
    if ok:
        derived = Ed25519PrivateKey.from_private_bytes(raw_seed[2:34]).public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw)
        ok = derived == raw_pub[1:33]
    print("ok" if ok else "mismatch")


def check(directory, path, key, regex):
    data = kv_get(load_env(directory), path) or {}
    print("ok" if key in data and re.fullmatch(regex, data[key]) else "mismatch")


def secret_equals(directory, state_path, ref, skey, expected):
    env = load_env(directory)
    namespace, name = ref.split("/", 1)
    secret = load_state(state_path).get("Secret/%s/%s" % (namespace, name), {})
    if skey not in secret.get("data", {}):
        print("mismatch")
        return

    def value(match):
        data = kv_get(env, match.group(1)) or {}
        return data.get(match.group(2), "\0missing")

    want = re.sub(r"<<([^#<>]+)#([a-z0-9_]+)>>", value, expected)
    print("ok" if base64.b64decode(secret["data"][skey]).decode() == want else "mismatch")


def all_values(directory, out_path):
    env = load_env(directory)
    found = []
    stack, seen = [""], set()
    while stack:
        prefix = stack.pop()
        run = bao(env, ["kv", "list", "-format=json", "-mount=" + MOUNT, prefix or "/"], check=False)
        if run.returncode != 0:
            continue
        for item in json.loads(run.stdout):
            path = prefix + item
            if item.endswith("/"):
                stack.append(path)
            elif path not in seen:
                seen.add(path)
                for val in (kv_get(env, path) or {}).values():
                    if isinstance(val, str) and len(val) >= 8:
                        found.append(val)
    with open(out_path, "w", encoding="utf-8") as handle:
        handle.write("".join(v + "\n" for v in found))
    print(len(found))


def count_entries(directory, prefix):
    env = load_env(directory)
    count, stack = 0, [prefix.rstrip("/") + "/"]
    while stack:
        current = stack.pop()
        run = bao(env, ["kv", "list", "-format=json", "-mount=" + MOUNT, current], check=False)
        if run.returncode != 0:
            if run.stdout.strip() == "{}" or "No value found" in run.stderr:
                continue
            raise RuntimeError("bao kv list %s failed: %s" % (current, run.stderr.strip()[-300:]))
        for item in json.loads(run.stdout):
            if item.endswith("/"):
                stack.append(current + item)
            else:
                count += 1
    print(count)


def test_registry(src, out):
    """The role registry (its templates included) plus test-only credentials,
    Secrets and templates."""
    import yaml  # PyYAML ships with ansible-core

    with open(src, encoding="utf-8") as handle:
        reg = yaml.safe_load(handle)
    reg["templates"]["zz-embed"] = "x-${0}"
    base = {"owner_role": "app_secrets", "legacy": [], "local": {"mechanism": "role_managed"},
            "rotate": {"none": True, "reason": "test"}, "identifiers": {}}

    def cred(cid, keys, **extra):
        reg["credentials"][cid] = dict(base, path="erag/" + cid, keys=keys, **extra)

    cred("zz-test/generators", {"hex_key": {"generate": {"type": "hex", "bytes": 16}},
                                "special": {"generate": {"type": "password", "length": 24, "special": True}}})
    cred("zz-test/bad-literal", {"password": {"generate": {"type": "password", "length": 16}}},
         identifiers={"bad": "x@@SK:zz@@"})
    cred("zz-test/plain", {"password": {"generate": {"type": "password", "length": 16}}})
    cred("zz-test/dep-a", {"password": {"generate": {"type": "password", "length": 16}}})
    cred("zz-test/special-embed", {"password": {"generate": {"type": "password", "length": 16, "special": True}}})
    # Written by the test with key a only: b was "added to the registry later".
    cred("zz-test/two-keys", {"a": {"generate": {"type": "password", "length": 16}},
                              "b": {"generate": {"type": "password", "length": 16}}})
    cred("zz-test/vf", {"password": {"generate": {"type": "password", "length": 16}}})
    reg["secrets"]["zz-test/zz-value-from"] = {"data": {"A": {"from": "zz-test/vf.password"},
                                                        "B": {"value_from": "zz_unset_fact.KEY"}}}
    reg["secrets"]["zz-test/zz-generators"] = {"data": {"HEX": {"from": "zz-test/generators.hex_key"},
                                                        "SPECIAL": {"from": "zz-test/generators.special"}}}
    reg["secrets"]["zz-test/zz-bad"] = {"data": {"A": {"identifier": "zz-test/bad-literal.bad"},
                                                 "B": {"from": "zz-test/bad-literal.password"}}}
    reg["secrets"]["zz-test/zz-undefined"] = {"data": {"A": {"template": "no-such-template",
                                                             "sources": ["zz-test/plain.password"]}}}
    reg["secrets"]["zz-test/zz-embed-static"] = {"data": {"A": {"template": "zz-embed",
                                                                "sources": ["user/hf-token.token"]}}}
    reg["secrets"]["zz-test/zz-embed-special"] = {"data": {"A": {"template": "zz-embed",
                                                                 "sources": ["zz-test/special-embed.password"]}}}
    reg["secrets"]["zz-test/zz-dep"] = {"data": {"A": {"from": "zz-test/dep-a.password"},
                                                 "B": {"from": "zz-test/two-keys.b"}}}
    with open(out, "w", encoding="utf-8") as handle:
        yaml.safe_dump(reg, handle, sort_keys=False)


def secret_matches(directory, state_path, expected_path):
    """Each expected Secret ({ns/name: {key: text with <<path#key>>}}) against the
    one the fake ESO made: one line per Secret, key names only, never a value."""
    env = load_env(directory)
    state = load_state(state_path)
    with open(expected_path, encoding="utf-8") as handle:
        expected = json.load(handle)["secrets"]
    cache = {}

    def value(match):
        if match.group(1) not in cache:
            cache[match.group(1)] = kv_get(env, match.group(1)) or {}
        return cache[match.group(1)].get(match.group(2), "\0missing")

    for ref in sorted(expected):
        namespace, name = ref.split("/", 1)
        secret = state.get("Secret/%s/%s" % (namespace, name))
        if secret is None:
            print("mismatch %s: no Secret" % ref)
            continue
        have = {k: base64.b64decode(v).decode() for k, v in secret.get("data", {}).items()}
        want = {k: re.sub(r"<<([^#<>]+)#([a-z0-9_]+)>>", value, v) for k, v in expected[ref].items()}
        missing = sorted(set(want) - set(have))
        extra = sorted(set(have) - set(want))
        differ = sorted(k for k in set(want) & set(have) if want[k] != have[k])
        if missing or extra or differ:
            print("mismatch %s: missing %s extra %s differ %s" % (ref, missing, extra, differ))
        else:
            print("ok %s" % ref)


def digest(directory, path):
    """sha256 of the entry's data (to compare before/after without a value)."""
    data = kv_get(load_env(directory), path)
    print(hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest() if data else "none")


# --- migration (test_migration.yaml) ------------------------------------------------------


def seed_legacy(state_path, spec_path, cred_file, values_out):
    """Seeds the Secrets and files of a local-mode env; values only go to values_out."""
    import yaml  # PyYAML ships with ansible-core

    with open(spec_path, encoding="utf-8") as handle:
        spec = json.load(handle)
    with open(cred_file, encoding="utf-8") as handle:
        file_values = yaml.safe_load(handle) or {}
    state = load_state(state_path)
    values, chosen = [], {}

    def secret(namespace, name):
        return state.setdefault("Secret/%s/%s" % (namespace, name), {
            "apiVersion": "v1", "kind": "Secret", "type": "Opaque",
            "metadata": {"name": name, "namespace": namespace}, "data": {}})

    def mark(obj, ref_var, user):
        meta = obj["metadata"]
        meta.setdefault("labels", {})[spec["markup_label"]] = "true"
        meta.setdefault("annotations", {})[spec["markup_annotation"]] = json.dumps({ref_var: user or ""})

    for ref in spec["refs"]:
        ident = (ref["id"], ref["kv_key"])
        if ident not in chosen:
            fv = ref.get("file_var")
            chosen[ident] = str(file_values[fv]) if fv and fv in file_values else secrets.token_urlsafe(24)
        obj = secret(ref["namespace"], ref["name"])
        obj["data"][ref["key"]] = base64.b64encode(chosen[ident].encode()).decode()
        if ref.get("markup"):
            mark(obj, ref.get("file_var") or ref["key"], ref.get("user"))
    for extra in spec.get("extra", []):
        obj = secret(extra["namespace"], extra["name"])
        for k in extra.get("data_keys", []):
            val = secrets.token_urlsafe(24)
            values.append(val)
            obj["data"][k] = base64.b64encode(val.encode()).decode()
        if extra.get("markup"):
            mark(obj, "PLATFORM", "admin")
    for ref in spec["helm_owned"]:
        namespace, name = ref.split("/", 1)
        meta = state["Secret/%s/%s" % (namespace, name)]["metadata"]
        meta.setdefault("labels", {})["app.kubernetes.io/managed-by"] = "Helm"
        meta.setdefault("annotations", {})["meta.helm.sh/release-name"] = namespace
    values.extend(chosen.values())
    releases = []
    for rel in spec.get("helm_releases", []):
        releases.append({k: rel[k] for k in ("name", "namespace", "chart")})
        top = max(rel["revisions"])
        for rev in rel["revisions"]:
            status = (rel.get("statuses") or {}).get(str(rev), "deployed" if rev == top else "superseded")
            values.append(release_secret(state, rel["namespace"], rel["name"], rev, status))
    state["FakeHelm//releases"] = {"releases": releases}
    save_state(state_path, state)
    # The other local artifacts: default_credentials.txt, a tmp render, an old log.
    everything = "\n".join("%s=%s" % (i[0], v) for i, v in sorted(chosen.items())) + "\n"
    for path in (spec["txt_file"], spec["tmp_file"], spec["old_log"]):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(everything)
    old = time.time() - 2 * 86400
    os.utime(spec["old_log"], (old, old))
    with open(values_out, "a", encoding="utf-8") as handle:
        handle.write("".join(v + "\n" for v in values if len(v) >= 8))
    print(len(values))


def release_secret(state, namespace, name, rev, status):
    """A Helm release storage Secret holding a (fake) value; returns the value."""
    val = secrets.token_urlsafe(24)
    state["Secret/%s/sh.helm.release.v1.%s.v%d" % (namespace, name, rev)] = {
        "apiVersion": "v1", "kind": "Secret", "type": "helm.sh/release.v1",
        "metadata": {"name": "sh.helm.release.v1.%s.v%d" % (name, rev), "namespace": namespace,
                     "labels": {"owner": "helm", "name": name, "version": str(rev), "status": status}},
        "data": {"release": base64.b64encode(("values: " + val).encode()).decode()}}
    return val


def helm_upgrade(state_path, namespace, name, status):
    """A new revision of the release (no value: openbao-mode values); the deployed one is superseded."""
    state = load_state(state_path)
    prefix = "Secret/%s/sh.helm.release.v1.%s.v" % (namespace, name)
    revs = sorted(int(k[len(prefix):]) for k in state if k.startswith(prefix))
    for rev in revs:
        labels = state[prefix + str(rev)]["metadata"]["labels"]
        if status == "deployed" and labels.get("status") == "deployed":
            labels["status"] = "superseded"
    new = (revs[-1] if revs else 0) + 1
    release_secret(state, namespace, name, new, status)
    state[prefix + str(new)]["data"] = {"release": base64.b64encode(b"values: none").decode()}
    save_state(state_path, state)
    print(new)


def secret_digests(state_path, out_path):
    state = load_state(state_path)
    out = {}
    for key, obj in state.items():
        if key.startswith("Secret/") and "/sh.helm.release." not in key:
            ref = key.split("/", 1)[1]
            for k, v in (obj.get("data") or {}).items():
                out["%s#%s" % (ref, k)] = hashlib.sha256(base64.b64decode(v)).hexdigest()
    with open(out_path, "w", encoding="utf-8") as handle:
        json.dump(out, handle, sort_keys=True)
    print(len(out))


def helm_drop(state_path, refs):
    state = load_state(state_path)
    for ref in refs:
        key = "Secret/" + ref
        obj = state.get(key)
        if obj is None:
            print("missing %s" % ref)
        elif ((obj.get("metadata") or {}).get("annotations") or {}).get("helm.sh/resource-policy") == "keep":
            print("kept %s" % ref)
        else:
            del state[key]
            print("deleted %s" % ref)
    save_state(state_path, state)


def fake_helm(args):
    if os.environ.get("FAKE_HELM_FAIL"):
        sys.stderr.write("Error: Kubernetes cluster unreachable (test)\n")
        return 1
    state = load_state(os.environ["FAKE_K8S_STATE"])
    releases = state.get("FakeHelm//releases", {}).get("releases", [])

    def revisions(rel):
        prefix = "Secret/%s/sh.helm.release.v1.%s.v" % (rel["namespace"], rel["name"])
        return sorted(int(k[len(prefix):]) for k in state if k.startswith(prefix))

    if args[:1] == ["list"]:
        print(json.dumps([{"name": r["name"], "namespace": r["namespace"], "revision": str(max(revisions(r) or [0])),
                           "chart": r["chart"], "status": "deployed", "app_version": "1"} for r in releases]))
        return 0
    if args[:1] == ["history"] and len(args) > 1:
        namespace = args[args.index("--namespace") + 1] if "--namespace" in args else "default"
        for rel in releases:
            if rel["name"] == args[1] and rel["namespace"] == namespace:
                prefix = "Secret/%s/sh.helm.release.v1.%s.v" % (rel["namespace"], rel["name"])
                print(json.dumps([{"revision": r, "status": state[prefix + str(r)]["metadata"]["labels"]["status"],
                                   "updated": "2026-10-03T00:00:00Z"} for r in revisions(rel)]))
                return 0
        sys.stderr.write("Error: release: not found\n")
        return 1
    sys.stderr.write("fake helm: unsupported %s\n" % " ".join(args[:2]))
    return 1


# --- rotation (test_rotation.yaml): Postgres, fake Redis and Keycloak, rollouts -----------

PG_IMAGE = os.environ.get("FAKE_POSTGRES_IMAGE", "ghcr.io/cloudnative-pg/postgresql:17")


def pg_start(directory):
    """A real Postgres (SCRAM-SHA-256 for TCP logins) on 127.0.0.1, in Docker."""
    port = free_port()
    container = "app-secrets-test-pg-" + secrets.token_hex(4)
    subprocess.run(["docker", "run", "-d", "--rm", "--name", container, "--network", "host", "--user", "26",
                    "--tmpfs", "/tmp/pg:uid=26,mode=0700", "--entrypoint", "bash", PG_IMAGE, "-c",
                    "initdb -D /tmp/pg/d -U postgres --auth-local=trust --auth-host=scram-sha-256 >/dev/null "
                    "&& exec postgres -D /tmp/pg/d -c listen_addresses=127.0.0.1 -p %d -k /tmp/pg" % port],
                   check=True, capture_output=True)
    # Written first, so pg-stop removes the container even when it never got ready.
    with open(os.path.join(directory, "pg.json"), "w", encoding="utf-8") as handle:
        json.dump({"container": container, "port": port}, handle)
    for _ in range(150):
        if subprocess.run(["docker", "exec", container, "pg_isready", "-h", "/tmp/pg", "-p", str(port)],
                          capture_output=True, check=False).returncode == 0:
            break
        time.sleep(0.2)
    else:
        raise RuntimeError("Postgres test container did not start")
    print(json.dumps({"port": port, "container": container}))


def pg_env(directory):
    with open(os.path.join(directory, "pg.json"), encoding="utf-8") as handle:
        return json.load(handle)


def pg_stop(directory):
    try:
        subprocess.run(["docker", "rm", "-f", pg_env(directory)["container"]], capture_output=True, check=False)
    except OSError:
        pass


def pg_user(directory, user, database, path, key):
    """A superuser role (as POSTGRES_USER is) whose password is the KV value, and its database."""
    pg = pg_env(directory)
    value = kv_get(load_env(directory), path)[key]
    sql = "CREATE ROLE \"%s\" LOGIN SUPERUSER PASSWORD '%s';\nCREATE DATABASE \"%s\" OWNER \"%s\";\n" % (
        user, value, database, user)
    run = subprocess.run(["docker", "exec", "-i", pg["container"], "psql", "-q", "-v", "ON_ERROR_STOP=1", "-h",
                          "/tmp/pg", "-p", str(pg["port"]), "-U", "postgres", "-d", "postgres"],
                         input=sql, capture_output=True, text=True, check=False)
    print("rc=%d" % run.returncode)


def pg_login(directory, user, database, path, key, version=None):
    """ok when a TCP (SCRAM) login with the KV value (at version) works, else denied."""
    pg = pg_env(directory)
    data = kv_get_version(load_env(directory), path, version) or {}
    env = dict(os.environ, PGPASSWORD=data.get(key, "\0missing").replace("\0", ""))
    run = subprocess.run(["docker", "exec", "-e", "PGPASSWORD", pg["container"], "psql", "-h", "127.0.0.1", "-p",
                          str(pg["port"]), "-U", user, "-d", database, "-tAc", "select 1"],
                         capture_output=True, text=True, check=False, env=env)
    print("ok" if run.returncode == 0 and run.stdout.strip() == "1" else "denied")


def pg_role_has_verifier(directory, user):
    """ok when the role's stored password is a SCRAM-SHA-256 verifier (never printed)."""
    pg = pg_env(directory)
    run = subprocess.run(["docker", "exec", pg["container"], "psql", "-h", "/tmp/pg", "-p", str(pg["port"]),
                          "-U", "postgres", "-tAc",
                          "select rolpassword like 'SCRAM-SHA-256$4096:%%' from pg_authid where rolname = '%s'" % user],
                         capture_output=True, text=True, check=False)
    print("ok" if run.stdout.strip() == "t" else "mismatch")


FAKES_LOCK = threading.Lock()


def fakes_path(directory):
    return os.path.join(directory, "fakes.json")


def fakes_load(directory):
    import fcntl

    with open(fakes_path(directory) + ".lock", "w", encoding="utf-8") as lock:
        fcntl.flock(lock, fcntl.LOCK_SH)
        with open(fakes_path(directory), encoding="utf-8") as handle:
            return json.load(handle)


def fakes_update(directory, change):
    """change(state) under an exclusive lock (the daemon and the CLI share the file)."""
    import fcntl

    with open(fakes_path(directory) + ".lock", "w", encoding="utf-8") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        with open(fakes_path(directory), encoding="utf-8") as handle:
            st = json.load(handle)
        out = change(st)
        tmp = fakes_path(directory) + ".tmp"
        with open(tmp, "w", encoding="utf-8") as handle:
            json.dump(st, handle)
        os.replace(tmp, fakes_path(directory))
        return out


def sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


def take_injected(flag):
    """A fakes_update change: True (and one less) while inject.<flag> > 0."""
    def change(st):
        left = int(st["inject"].get(flag) or 0)
        if left > 0:
            st["inject"][flag] = left - 1
            return True
        return False
    return change


def serve_fakes(directory, redis_port, kc_port, ready):
    """A RESP server (AUTH, PING, ACL SETUSER with resetpass / #<sha256> / ><pw>)
    and the Keycloak admin REST calls the rotator makes, both over fakes.json."""
    import socketserver
    from http.server import ThreadingHTTPServer

    class RedisHandler(socketserver.StreamRequestHandler):
        def reply(self, text):
            self.wfile.write(text.encode() + b"\r\n")

        def read_command(self):
            head = self.rfile.readline()
            if not head:
                return None
            if not head.startswith(b"*"):
                return head.decode().split()
            args = []
            for _ in range(int(head[1:])):
                n = int(self.rfile.readline()[1:])
                args.append(self.rfile.read(n + 2)[:-2].decode())
            return args

        def handle(self):
            user = None
            while True:
                args = self.read_command()
                if not args:
                    return
                cmd = args[0].upper()
                st = fakes_load(directory)
                fakes_update(directory, lambda s: s["log"].append({"redis": cmd, "args": len(args)}))
                if cmd == "AUTH":
                    name, pw = (args[1], args[2]) if len(args) == 3 else ("default", args[1])
                    if st["redis"]["users"].get(name) == sha(pw):
                        user = name
                        self.reply("+OK")
                    else:
                        self.reply("-WRONGPASS invalid username-password pair or user is disabled.")
                elif user is None:
                    self.reply("-NOAUTH Authentication required.")
                elif cmd == "PING":
                    self.reply("+PONG")
                elif cmd == "ACL" and len(args) >= 3 and args[1].upper() == "SETUSER":
                    if fakes_update(directory, take_injected("redis_acl_fail")):
                        self.reply("-ERR injected failure (test)")
                        continue

                    def setuser(s, name=args[2], rules=args[3:]):
                        for r in rules:
                            if r == "resetpass":
                                s["redis"]["users"][name] = None
                            elif r.startswith("#"):
                                s["redis"]["users"][name] = r[1:]
                            elif r.startswith(">"):
                                s["redis"]["users"][name] = sha(r[1:])
                                s["redis"]["plaintext_rules"] += 1
                    fakes_update(directory, setuser)
                    self.reply("+OK")
                elif cmd == "QUIT":
                    self.reply("+OK")
                    return
                else:
                    self.reply("-ERR unknown command (test)")

    class KcHandler(BaseHTTPRequestHandler):
        def send(self, code, body=None):
            data = json.dumps(body).encode() if body is not None else b""
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def body(self):
            return self.rfile.read(int(self.headers.get("Content-Length", 0)) or 0)

        def authed(self, st):
            return self.headers.get("Authorization", "").replace("Bearer ", "", 1) in st["keycloak"]["tokens"]

        def client(self, st, realm, cid):
            for name, c in st["keycloak"]["realms"].get(realm, {}).items():
                if c["id"] == cid:
                    return name
            return None

        def do_POST(self):  # noqa: N802 (http.server API)
            form = urllib.parse.parse_qs(self.body().decode())
            st = fakes_load(directory)
            ok = (self.path == "/realms/master/protocol/openid-connect/token"
                  and form.get("grant_type") == ["password"] and form.get("client_id") == ["admin-cli"]
                  and form.get("username") == [st["keycloak"]["admin_user"]]
                  and sha(form.get("password", [""])[0]) == st["keycloak"]["admin_sha"])
            if not ok:
                return self.send(401, {"error": "invalid_grant", "error_description": "Invalid user credentials"})
            token = secrets.token_hex(16)
            fakes_update(directory, lambda s: s["keycloak"]["tokens"].append(token))
            return self.send(200, {"access_token": token, "expires_in": 60})

        def do_GET(self):  # noqa: N802 (http.server API)
            st = fakes_load(directory)
            if not self.authed(st):
                return self.send(401, {"error": "HTTP 401 Unauthorized"})
            url = urllib.parse.urlparse(self.path)
            parts = url.path.strip("/").split("/")
            if len(parts) == 4 and parts[:2] == ["admin", "realms"] and parts[3] == "clients":
                want = urllib.parse.parse_qs(url.query).get("clientId", [""])[0]
                clients = st["keycloak"]["realms"].get(parts[2], {})
                return self.send(200, [{"id": c["id"], "clientId": n} for n, c in clients.items() if n == want])
            if len(parts) == 6 and parts[3] == "clients" and parts[5] == "client-secret":
                name = self.client(st, parts[2], parts[4])
                if name is None:
                    return self.send(404, {"error": "Could not find client"})
                value = st["keycloak"]["realms"][parts[2]][name]["secret"]
                # One wrong read-back after an injected PUT (the verify step).
                if fakes_update(directory, lambda s: s["keycloak"].pop("wrong_next_get", False)):
                    value = secrets.token_hex(16)
                return self.send(200, {"type": "secret", "value": value})
            return self.send(404, {"error": "not found (test)"})

        def do_PUT(self):  # noqa: N802 (http.server API)
            st = fakes_load(directory)
            body = json.loads(self.body() or b"{}")
            if not self.authed(st):
                return self.send(401, {"error": "HTTP 401 Unauthorized"})
            parts = urllib.parse.urlparse(self.path).path.strip("/").split("/")
            name = self.client(st, parts[2], parts[4]) if len(parts) == 5 and parts[3] == "clients" else None
            if name is None:
                return self.send(404, {"error": "Could not find client"})
            if fakes_update(directory, take_injected("kc_put_fail")):
                return self.send(500, {"errorMessage": "injected failure (test)"})

            def put(s, realm=parts[2], client=name, secret=body.get("secret")):
                s["keycloak"]["realms"][realm][client]["secret"] = secret
                s["keycloak"]["puts"] += 1
                if take_injected("kc_readback_wrong")(s):
                    s["keycloak"]["wrong_next_get"] = True
            fakes_update(directory, put)
            return self.send(204)

        def log_message(self, *args):
            pass

    socketserver.ThreadingTCPServer.allow_reuse_address = True
    redis = socketserver.ThreadingTCPServer(("127.0.0.1", redis_port), RedisHandler)
    kc = ThreadingHTTPServer(("127.0.0.1", kc_port), KcHandler)
    threading.Thread(target=redis.serve_forever, daemon=True).start()
    threading.Thread(target=kc.serve_forever, daemon=True).start()
    with open(ready, "w", encoding="utf-8") as handle:
        handle.write("ok")
    while True:
        time.sleep(3600)


def fakes_start(directory):
    redis_port, kc_port = free_port(), free_port()
    with open(fakes_path(directory), "w", encoding="utf-8") as handle:
        json.dump({"redis": {"users": {}, "plaintext_rules": 0},
                   "keycloak": {"admin_user": "admin", "admin_sha": "", "realms": {}, "tokens": [], "puts": 0},
                   "inject": {}, "log": []}, handle)
    ready = os.path.join(directory, "fakes.ready")
    child = subprocess.Popen([sys.executable, os.path.abspath(__file__), "serve-fakes", directory, str(redis_port),
                              str(kc_port), ready], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                             start_new_session=True)
    for _ in range(100):
        if os.path.exists(ready):
            break
        time.sleep(0.1)
    else:
        raise RuntimeError("fake Redis/Keycloak did not start")
    with open(os.path.join(directory, "fakes-env.json"), "w", encoding="utf-8") as handle:
        json.dump({"pid": child.pid, "redis_port": redis_port, "kc_port": kc_port}, handle)
    print(json.dumps({"redis_port": redis_port, "kc_port": kc_port}))


def fakes_stop(directory):
    try:
        with open(os.path.join(directory, "fakes-env.json"), encoding="utf-8") as handle:
            os.killpg(json.load(handle)["pid"], 15)
    except (OSError, ValueError, KeyError):
        pass


def fakes_set(directory, key, value):
    """fakes-set <dir> inject.<flag> <n>: the next n calls fail (no value ever)."""
    section, name = key.split(".", 1)

    def change(st):
        st[section][name] = json.loads(value)
    fakes_update(directory, change)


def redis_user(directory, user, path, key):
    value = kv_get(load_env(directory), path)[key]
    fakes_update(directory, lambda st: st["redis"]["users"].update({user: sha(value)}))


def redis_login(directory, user, path, key, version=None):
    data = kv_get_version(load_env(directory), path, version) or {}
    want = fakes_load(directory)["redis"]["users"].get(user)
    print("ok" if key in data and want == sha(data[key]) else "denied")


def kc_admin(directory, state_path, namespace, name):
    """A random Keycloak admin password: in the fake Keycloak and in the platform Secret."""
    pw = secrets.token_hex(16)
    fakes_update(directory, lambda st: st["keycloak"].update({"admin_sha": sha(pw)}))
    state = load_state(state_path)
    state["Secret/%s/%s" % (namespace, name)] = {
        "apiVersion": "v1", "kind": "Secret", "metadata": {"name": name, "namespace": namespace},
        "data": {"password": base64.b64encode(pw.encode()).decode(),
                 "username": base64.b64encode(b"admin").decode()}}
    save_state(state_path, state)
    with open(os.path.join(directory, "values.extra"), "a", encoding="utf-8") as handle:
        handle.write(pw + "\n")


def kc_client(directory, realm, client_id, path, key):
    value = kv_get(load_env(directory), path)[key]

    def change(st):
        st["keycloak"]["realms"].setdefault(realm, {})[client_id] = {
            "id": "uuid-" + secrets.token_hex(4), "secret": value}
    fakes_update(directory, change)


def kc_secret_is(directory, realm, client_id, path, key, version=None):
    data = kv_get_version(load_env(directory), path, version) or {}
    have = fakes_load(directory)["keycloak"]["realms"].get(realm, {}).get(client_id, {}).get("secret")
    print("ok" if key in data and have == data[key] else "mismatch")


def kv_same(directory, path, version_a, version_b):
    """ok when two versions of the entry hold the same data (never printed)."""
    env = load_env(directory)
    a, b = kv_get_version(env, path, version_a), kv_get_version(env, path, version_b)
    print("ok" if a is not None and a == b else "differ")


def kv_key_differs(directory, path, key, version_a, version_b):
    """ok when <key> differs between the versions and every other key is equal."""
    env = load_env(directory)
    a, b = kv_get_version(env, path, version_a) or {}, kv_get_version(env, path, version_b) or {}
    others = (set(a) | set(b)) - {key}
    print("ok" if a.get(key) and b.get(key) and a[key] != b[key] and all(a.get(k) == b.get(k) for k in others)
          else "mismatch")


def all_versions(directory, out_path):
    """Every value of every version of every entry (the rotation leak grep)."""
    env = load_env(directory)
    found = []
    stack = [""]
    while stack:
        prefix = stack.pop()
        run = bao(env, ["kv", "list", "-format=json", "-mount=" + MOUNT, prefix or "/"], check=False)
        if run.returncode != 0:
            continue
        for item in json.loads(run.stdout):
            path = prefix + item
            if item.endswith("/"):
                stack.append(path)
                continue
            meta = bao(env, ["kv", "metadata", "get", "-format=json", "-mount=" + MOUNT, path], check=False)
            if meta.returncode != 0:
                continue
            for version in (json.loads(meta.stdout).get("data") or {}).get("versions", {}):
                for val in (kv_get_version(env, path, version) or {}).values():
                    if isinstance(val, str) and len(val) >= 8:
                        found.append(val)
    extra = os.path.join(directory, "values.extra")
    if os.path.exists(extra):
        with open(extra, encoding="utf-8") as handle:
            found.extend(line.strip() for line in handle if line.strip())
    with open(out_path, "w", encoding="utf-8") as handle:
        handle.write("".join(v + "\n" for v in sorted(set(found))))
    print(len(set(found)))


def run_rollout(state_path, key):
    """Plays the workload controller after a pod-template patch: the rollout
    finishes at once, unless FAKE_ROLLOUT_STUCK names the workload."""
    state = load_state(state_path)
    obj = state[key]
    if obj["metadata"]["name"] in os.environ.get("FAKE_ROLLOUT_STUCK", "").split(","):
        return
    want = (obj.get("spec") or {}).get("replicas", 1)
    status = obj.setdefault("status", {})
    status["observedGeneration"] = obj["metadata"].get("generation", 1)
    if obj["kind"] == "DaemonSet":
        status.update({"desiredNumberScheduled": want, "updatedNumberScheduled": want, "numberAvailable": want})
    else:
        status.update({"replicas": want, "updatedReplicas": want, "availableReplicas": want, "readyReplicas": want})
        if obj["kind"] == "StatefulSet":
            status["currentRevision"] = status["updateRevision"] = "rev-%s" % status["observedGeneration"]
    save_state(state_path, state)



def main():
    cmd, args = sys.argv[1], sys.argv[2:]
    if cmd == "serve-tokenreview":
        threading.Thread(target=serve_tokenreview, args=(int(args[0]), args[1]), daemon=True).start()
        while True:
            time.sleep(3600)
    elif cmd == "start":
        start(args[0])
    elif cmd == "stop":
        stop(args[0])
    elif cmd == "hook":
        kind = args[1].split("/", 1)[0]
        if kind == "Job":
            run_job(args[0], args[1])
        elif kind == "ExternalSecret":
            run_eso(args[0], args[1])
        elif kind in ("Deployment", "StatefulSet", "DaemonSet"):
            run_rollout(args[0], args[1])
    elif cmd == "root":
        run = bao(load_env(args[0]), args[1:], check=False)
        print("rc=%d" % run.returncode)
    elif cmd == "verify-nkey":
        verify_nkey(*args)
    elif cmd == "check":
        check(*args)
    elif cmd == "secret-equals":
        secret_equals(*args)
    elif cmd == "values":
        all_values(args[0], args[1])
    elif cmd == "count":
        count_entries(args[0], args[1])
    elif cmd == "put-random":
        # put-random <dir> <path> <key> [<key> ...]: a new entry holding these keys.
        rc = 0
        for i, key in enumerate(args[2:]):
            value = secrets.token_hex(16)
            run = bao(load_env(args[0]), ["kv", "put" if i == 0 else "patch", "-mount=" + MOUNT, args[1], key + "=-"],
                      stdin=value, check=False)
            rc = rc or run.returncode
        print("rc=%d" % rc)
    elif cmd == "secret-matches":
        secret_matches(*args)
    elif cmd == "test-registry":
        test_registry(*args)
    elif cmd == "joblogs":
        # Every worker log line of the run (for the no-value-in-output grep).
        st = load_state(args[0])
        with open(args[1], "w", encoding="utf-8") as handle:
            for k in sorted(st):
                if k.startswith("JobLog/"):
                    handle.write("".join(line + "\n" for line in st[k]["lines"]))
    elif cmd == "digest":
        digest(*args)
    elif cmd == "seed-legacy":
        seed_legacy(*args)
    elif cmd == "helm-upgrade":
        helm_upgrade(*args)
    elif cmd == "secret-digests":
        secret_digests(*args)
    elif cmd == "helm-drop":
        helm_drop(args[0], args[1:])
    elif cmd == "fake-helm":
        sys.exit(fake_helm(args))
    elif cmd == "pg-start":
        pg_start(args[0])
    elif cmd == "pg-stop":
        pg_stop(args[0])
    elif cmd == "pg-user":
        pg_user(*args)
    elif cmd == "pg-login":
        pg_login(*args)
    elif cmd == "pg-verifier":
        pg_role_has_verifier(*args)
    elif cmd == "serve-fakes":
        serve_fakes(args[0], int(args[1]), int(args[2]), args[3])
    elif cmd == "fakes-start":
        fakes_start(args[0])
    elif cmd == "fakes-stop":
        fakes_stop(args[0])
    elif cmd == "fakes-set":
        fakes_set(*args)
    elif cmd == "fakes-get":
        # fakes-get <dir> <section>.<name>: a counter or flag (never a value).
        section, name = args[1].split(".", 1)
        print(json.dumps(fakes_load(args[0])[section][name]))
    elif cmd == "redis-user":
        redis_user(*args)
    elif cmd == "redis-login":
        redis_login(*args)
    elif cmd == "kc-admin":
        kc_admin(*args)
    elif cmd == "kc-client":
        kc_client(*args)
    elif cmd == "kc-secret-is":
        kc_secret_is(*args)
    elif cmd == "kv-same":
        kv_same(*args)
    elif cmd == "kv-key-differs":
        kv_key_differs(*args)
    elif cmd == "kv-version":
        # kv-version <dir> <path>: the current version number (metadata only).
        run = bao(load_env(args[0]), ["kv", "metadata", "get", "-format=json", "-mount=" + MOUNT, args[1]], check=False)
        print((json.loads(run.stdout).get("data") or {}).get("current_version", 0) if run.returncode == 0 else 0)
    elif cmd == "all-versions":
        all_versions(args[0], args[1])
    elif cmd == "rbac-allows":
        rbac = load_state(args[0])["FakeJobRuns//all"]["rbac"][args[1]]
        allowed = rbac_allows(rbac, WORKER_NS, LAYER + "-secrets-importer", args[2], args[3], args[4])
        print("allow" if allowed else "deny")
    else:
        raise SystemExit("unknown command " + cmd)


if __name__ == "__main__":
    main()
