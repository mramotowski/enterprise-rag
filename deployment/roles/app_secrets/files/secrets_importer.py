#!/usr/bin/env python3
# Copyright (C) 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0
"""app_secrets openbao adapter: the in-cluster importer (migration, AD-12).

Runs as the only container of the erag-secrets importer Job (python:3.12-slim,
standard library only), and in tests/test_migration.yaml.

    python3 secrets_importer.py

In this order, so that nothing changes unless everything before it succeeded:
  1. probe: OpenBao reachable, initialized and unsealed (sys/health), then a
     Kubernetes-auth login as OB_ROLE (erag-secrets-importer);
  2. read: every legacy Secret of the plan (Kubernetes API, get), and check
     each entry: every KV key has a value, and the sources of one key agree;
  3. compare: each entry's current value in OpenBao, if any: the same value
     is "exists" (not written again), another value is a "conflict" (never
     overwritten; the run stops before any write);
  4. write: the other entries with check-and-set cas=0 (an entry created
     meanwhile is compared again);
  5. patch (only when 1-4 succeeded): the hand-off annotation
     helm.sh/resource-policy: keep on every planned Secret that Helm manages
     (so the upgrade that stops templating it does not delete it, and its
     ExternalSecret adopts it), then the removal of the local markup label and
     annotation from the planned Secrets (platform Secrets: patch only, never
     read).

Inputs, all non-secret:
  BAO_ADDR, BAO_CACERT     OpenBao API address and CA bundle (ca.crt only)
  BAO_CLIENT_TIMEOUT       per-request timeout ("15s" or seconds)
  OB_AUTH_MOUNT, OB_ROLE   Kubernetes auth mount and role
  OB_JWT_FILE              projected ServiceAccount token (OpenBao audience)
  OB_PLAN_FILE             plan.json:
                             {"mount": <kv mount>,
                              "entries": [{"id", "path" (relative to the mount),
                                           "required": bool,
                                           "keys": {<kv_key>: [{"namespace", "name", "key"}, ...]}}],
                              "handover": [{"namespace", "name"}],
                              "unmark": [{"namespace", "name"}],
                              "markup_label", "markup_annotation"}
  KUBE_API, KUBE_CACERT    Kubernetes API address and CA (kube-root-ca.crt)
  KUBE_TOKEN_FILE          projected ServiceAccount token (API audience)

Secrets: legacy values and the OpenBao token live only in this process. They
are never printed, logged, written to a file or put in argv or env. No proxy
is used (both endpoints are in-cluster or the configured OpenBao).

Output (stdout): one line per result, "ERAG_SECRETS_RESULT <json>":
  {"kind":"probe","state":"ok|unreachable|uninitialized|sealed|login_failed","error":"..."}
  {"kind":"legacy","found":N,"error":""}      legacy Secrets found (0 = no local env)
  {"kind":"credential","id":"...","action":"import",
   "result":"created|exists|conflict|absent|missing|error","version":N,"error":"..."}
     absent: no legacy value (ensure generates it); missing: none, but the
     entry is required (the env has legacy Secrets).
  {"kind":"secret","namespace":"...","name":"...","action":"keep|unmark",
   "result":"patched|unchanged|skipped|missing|error","error":"..."}
     keep skipped: not managed by Helm; missing: the Secret does not exist.
  {"kind":"done","state":"ok|failed","error":"..."}   (always last)
Exit: 0 when every entry is created/exists/absent and every patch worked.
"""

import base64
import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

PREFIX = "ERAG_SECRETS_RESULT "
KEEP = "helm.sh/resource-policy"
HELM_LABEL = "app.kubernetes.io/managed-by"


def result(obj):
    sys.stdout.write(PREFIX + json.dumps(obj, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def log(msg):
    sys.stderr.write("erag-secrets-importer: %s\n" % msg)
    sys.stderr.flush()


class RunError(Exception):
    """Stops the run; the message never holds a value."""


def timeout_seconds(text):
    text = (text or "15s").strip()
    if text.endswith("s"):
        text = text[:-1]
    try:
        return max(1, int(text))
    except ValueError:
        return 15


class Http:
    """JSON over HTTPS with one CA file and no proxy."""

    def __init__(self, base, cafile, timeout):
        self.base = base.rstrip("/")
        ctx = ssl.create_default_context(cafile=cafile) if cafile else ssl.create_default_context()
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
                                                  urllib.request.HTTPSHandler(context=ctx))
        self.timeout = timeout

    def call(self, method, path, body=None, headers=None, content_type="application/json"):
        """Returns (status, parsed JSON or {}); status 0 = no HTTP answer."""
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(self.base + path, data=data, method=method)
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        if data is not None:
            req.add_header("Content-Type", content_type)
        try:
            with self.opener.open(req, timeout=self.timeout) as resp:
                raw = resp.read()
                status = resp.status
        except urllib.error.HTTPError as err:
            raw = err.read()
            status = err.code
        except (urllib.error.URLError, OSError, ValueError) as err:
            return 0, {"errors": [type(err).__name__ + ": " + str(getattr(err, "reason", err))[:200]]}
        try:
            doc = json.loads(raw) if raw else {}
        except ValueError:
            doc = {}
        return status, doc if isinstance(doc, dict) else {}


def errors_of(doc):
    """OpenBao {"errors": [...]} or Kubernetes Status message (no values)."""
    if isinstance(doc, dict):
        if doc.get("errors"):
            return "; ".join(str(e) for e in doc["errors"])[:300]
        if doc.get("message"):
            return str(doc["message"])[:300]
    return ""


def read_file(path, what):
    try:
        with open(path, encoding="utf-8") as handle:
            return handle.read().strip()
    except OSError as err:
        raise RunError("cannot read %s (%s): %s" % (what, path, err.strerror)) from None


class Importer:
    def __init__(self, env):
        self.env = env
        timeout = timeout_seconds(env.get("BAO_CLIENT_TIMEOUT"))
        addr = env.get("BAO_ADDR", "")
        if not addr.startswith("https://"):
            raise RunError("BAO_ADDR must be an https:// URL")
        api = env.get("KUBE_API", "https://kubernetes.default.svc")
        if not api.startswith("https://"):
            raise RunError("KUBE_API must be an https:// URL")
        self.bao = Http(addr, env.get("BAO_CACERT") or None, timeout)
        self.kube = Http(api, env.get("KUBE_CACERT") or None, timeout)
        self.plan = json.loads(read_file(env.get("OB_PLAN_FILE", ""), "OB_PLAN_FILE"))
        self.mount = self.plan["mount"]
        self.token = None
        self.kube_token = None
        self.failed = False
        self.done_error = ""

    # --- OpenBao ---------------------------------------------------------------------

    def probe(self):
        status, doc = self.bao.call("GET", "/v1/sys/health?standbyok=true&perfstandbyok=true"
                                    "&sealedcode=200&uninitcode=200")
        if status != 200 or "sealed" not in doc:
            state = "unreachable"
            msg = "cannot read the seal status of %s: %s" % (self.bao.base, errors_of(doc) or status)
        elif not doc.get("initialized", False):
            state, msg = "uninitialized", "OpenBao at %s is not initialized" % self.bao.base
        elif doc.get("sealed"):
            state, msg = "sealed", "OpenBao at %s is sealed" % self.bao.base
        else:
            state, msg = "ok", ""
        if state != "ok":
            result({"kind": "probe", "state": state, "error": msg})
            raise RunError("OpenBao is %s" % state)
        mount = self.env.get("OB_AUTH_MOUNT", "kubernetes")
        role = self.env.get("OB_ROLE", "")
        jwt = read_file(self.env.get("OB_JWT_FILE", ""), "OB_JWT_FILE")
        status, doc = self.bao.call("POST", "/v1/auth/%s/login" % urllib.parse.quote(mount, safe=""),
                                    {"role": role, "jwt": jwt})
        jwt = None
        token = ((doc.get("auth") or {}).get("client_token") or "") if status == 200 else ""
        if not token:
            result({"kind": "probe", "state": "login_failed",
                    "error": "login to auth/%s as role %s failed: %s" % (mount, role, errors_of(doc) or status)})
            raise RunError("login failed")
        self.token = token
        result({"kind": "probe", "state": "ok", "error": ""})

    def kv(self, method, path, body=None):
        return self.bao.call(method, "/v1/%s/data/%s" % (self.mount, urllib.parse.quote(path)), body,
                             {"X-Vault-Token": self.token})

    def revoke(self):
        if self.token:
            status, _ = self.bao.call("POST", "/v1/auth/token/revoke-self", {}, {"X-Vault-Token": self.token})
            if status not in (200, 204):
                log("token revoke failed (%s)" % status)
            self.token = None

    # --- Kubernetes ------------------------------------------------------------------

    def secret_path(self, ref):
        return "/api/v1/namespaces/%s/secrets/%s" % (urllib.parse.quote(ref["namespace"], safe=""),
                                                     urllib.parse.quote(ref["name"], safe=""))

    def kube_call(self, method, ref, body=None):
        if self.kube_token is None:
            self.kube_token = read_file(self.env.get("KUBE_TOKEN_FILE", ""), "KUBE_TOKEN_FILE")
        return self.kube.call(method, self.secret_path(ref), body, {"Authorization": "Bearer " + self.kube_token},
                              content_type="application/merge-patch+json")

    def get_secret(self, ref):
        """The Secret object, or None when it does not exist."""
        status, doc = self.kube_call("GET", ref)
        if status == 200:
            return doc
        if status == 404:
            return None
        raise RunError("get Secret %s/%s: %s %s" % (ref["namespace"], ref["name"], status, errors_of(doc)))

    # --- the run ---------------------------------------------------------------------

    def read_legacy(self):
        """{(ns, name): Secret or None} for every legacy ref, and the found count."""
        cache = {}
        for entry in self.plan["entries"]:
            for refs in entry["keys"].values():
                for ref in refs:
                    k = (ref["namespace"], ref["name"])
                    if k not in cache:
                        cache[k] = self.get_secret(ref)
        found = sum(1 for v in cache.values() if v is not None)
        result({"kind": "legacy", "found": found, "error": ""})
        return cache, found

    def evaluate(self, cache, found):
        """[(entry, data)] for entries to write; reports and returns the others' failures."""
        to_write, bad = [], 0
        for entry in self.plan["entries"]:
            data, missing, err = {}, [], ""
            for kv_key, refs in entry["keys"].items():
                values = {}
                for ref in refs:
                    secret = cache.get((ref["namespace"], ref["name"]))
                    raw = ((secret or {}).get("data") or {}).get(ref["key"])
                    if raw is None:
                        continue
                    try:
                        values["%s/%s.%s" % (ref["namespace"], ref["name"], ref["key"])] = \
                            base64.b64decode(raw, validate=True).decode("utf-8")
                    except (ValueError, UnicodeDecodeError):
                        err = "%s/%s key %s is not UTF-8 text" % (ref["namespace"], ref["name"], ref["key"])
                if len(set(values.values())) > 1:
                    err = err or "the sources of %s disagree: %s" % (kv_key, ", ".join(sorted(values)))
                if values:
                    data[kv_key] = next(iter(values.values()))
                else:
                    missing.append(kv_key)
                values = None
            if not err and data and missing:
                err = "found only %s; %s have no value in %s" % (
                    ", ".join(sorted(data)), ", ".join(missing),
                    ", ".join(sorted({"%s/%s" % (r["namespace"], r["name"])
                                      for k in missing for r in entry["keys"][k]})) or "no legacy Secret")
            if err:
                result({"kind": "credential", "id": entry["id"], "action": "import", "result": "error",
                        "version": 0, "error": err})
                bad += 1
            elif not data:
                required = entry.get("required") and found > 0
                where = ", ".join(sorted({"%s/%s.%s" % (r["namespace"], r["name"], r["key"])
                                          for refs in entry["keys"].values() for r in refs})) or "no legacy Secret"
                result({"kind": "credential", "id": entry["id"], "action": "import",
                        "result": "missing" if required else "absent", "version": 0,
                        "error": ("required, but no legacy value in %s (the running deployment's users or "
                                  "clients would keep a value the store does not hold; if the feature that uses it "
                                  "is enabled for the first time in this run, migrate with it disabled and enable "
                                  "it afterwards)" % where) if required else ""})
                bad += 1 if required else 0
            else:
                to_write.append((entry, data))
            data = None
        return to_write, bad

    def compare(self, entry, data):
        """(result, version, error) of the entry's current value: None = no entry."""
        status, doc = self.kv("GET", entry["path"])
        if status == 404 and not ((doc.get("data") or {}).get("metadata") or {}).get("version"):
            return None
        current = (doc.get("data") or {}).get("data") if status == 200 else None
        version = (((doc.get("data") or {}).get("metadata") or {}).get("version")) or 0
        if current is None:
            if status == 404:
                return "error", version, ("the current version of %s/%s is deleted; restore it (bao kv undelete) "
                                          "or remove its metadata, then re-run" % (self.mount, entry["path"]))
            return "error", version, "read %s/%s: %s" % (self.mount, entry["path"], errors_of(doc) or status)
        same = all(current.get(k) == v for k, v in data.items())
        current = None
        if same:
            return "exists", version, ""
        return "conflict", version, ("%s/%s already holds other values than the running deployment; it is "
                                     "not overwritten. Remove it (bao kv metadata delete) if it was "
                                     "written by mistake, then re-run" % (self.mount, entry["path"]))

    def write(self, entry, data):
        status, doc = self.kv("POST", entry["path"], {"options": {"cas": 0}, "data": data})
        if status in (200, 204):
            version = ((doc.get("data") or {}).get("version")) or 0
            return "created", version, ""
        err = errors_of(doc)
        if status == 400 and "check-and-set" in err:
            # Created between the compare and the write.
            return self.compare(entry, data) or ("error", 0, "CAS mismatch on %s/%s, then no entry"
                                                 % (self.mount, entry["path"]))
        return "error", 0, "write %s/%s: %s" % (self.mount, entry["path"], err or status)

    def patch(self, ref, action, body):
        status, doc = self.kube_call("PATCH", ref, body)
        if status == 200:
            return "patched", ""
        if status == 404:
            return "missing", ""
        return "error", "patch %s: %s %s" % (action, status, errors_of(doc))

    def handover(self):
        bad = 0
        for ref in self.plan.get("handover", []):
            try:
                secret = self.get_secret(ref)
            except RunError as err:
                res, msg = "error", str(err)
            else:
                meta = (secret or {}).get("metadata") or {}
                if secret is None:
                    res, msg = "missing", ""
                elif (meta.get("labels") or {}).get(HELM_LABEL) != "Helm":
                    res, msg = "skipped", ""
                elif (meta.get("annotations") or {}).get(KEEP) == "keep":
                    res, msg = "unchanged", ""
                else:
                    res, msg = self.patch(ref, "keep", {"metadata": {"annotations": {KEEP: "keep"}}})
            secret = None
            bad += res == "error"
            result({"kind": "secret", "namespace": ref["namespace"], "name": ref["name"], "action": "keep",
                    "result": res, "error": msg})
        label, annotation = self.plan["markup_label"], self.plan["markup_annotation"]
        for ref in self.plan.get("unmark", []):
            res, msg = self.patch(ref, "unmark", {"metadata": {"labels": {label: None},
                                                               "annotations": {annotation: None}}})
            bad += res == "error"
            result({"kind": "secret", "namespace": ref["namespace"], "name": ref["name"], "action": "unmark",
                    "result": res, "error": msg})
        return bad

    def run(self):
        self.probe()
        cache, found = self.read_legacy()
        to_write, bad = self.evaluate(cache, found)
        cache = None
        pending = []
        while to_write:
            entry, data = to_write.pop(0)
            current = self.compare(entry, data)
            if current is None:
                pending.append((entry, data))
            else:
                res, version, err = current
                bad += res != "exists"
                result({"kind": "credential", "id": entry["id"], "action": "import", "result": res,
                        "version": version, "error": err})
            data = None
        to_write = pending
        if bad:
            for entry, _ in to_write:
                result({"kind": "credential", "id": entry["id"], "action": "import", "result": "error",
                        "version": 0, "error": "not written: another credential failed its check"})
            raise RunError("one or more credentials failed their check; nothing was written")
        failed = 0
        while to_write:
            entry, data = to_write.pop(0)
            res, version, err = self.write(entry, data)
            data = None
            failed += res not in ("created", "exists")
            result({"kind": "credential", "id": entry["id"], "action": "import", "result": res,
                    "version": version, "error": err})
        if failed:
            raise RunError("one or more credentials could not be imported; no Secret was changed")
        if self.handover():
            raise RunError("one or more Secrets could not be patched")


def main():
    importer = None
    try:
        importer = Importer(os.environ)
        importer.run()
    except RunError as err:
        log(str(err))
        if importer:
            importer.revoke()
        result({"kind": "done", "state": "failed", "error": str(err)})
        return 1
    except Exception as err:  # noqa: BLE001 (report any crash without a traceback, which could hold data)
        log("unexpected %s" % type(err).__name__)
        if importer:
            importer.revoke()
        result({"kind": "done", "state": "failed", "error": "unexpected %s" % type(err).__name__})
        return 1
    importer.revoke()
    result({"kind": "done", "state": "ok", "error": ""})
    return 0


if __name__ == "__main__":
    sys.exit(main())
