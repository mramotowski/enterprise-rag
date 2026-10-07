#!/usr/bin/env python3
# Copyright (C) 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0
"""app_secrets openbao adapter: the in-cluster rotator (rotation, AD-9).

Runs as the only container of an erag-secrets rotator Job (python:3.12-slim,
standard library only, the worker ServiceAccount), one Job per credential, and
in tests/test_rotation.yaml.

    python3 secrets_rotator.py

For the credential of the plan, in this order:
  1. probe: OpenBao reachable, initialized and unsealed (sys/health), then a
     Kubernetes-auth login as OB_ROLE (erag-secrets-worker);
  2. read the current version V of the KV entry: it must be live and hold
     every key of the plan (operator-write stops here: the operator wrote the
     version, the adapter syncs it);
  3. precheck: the current value works on the server (Postgres login, Redis
     AUTH, Keycloak admin login and the client); a failure changes nothing;
  4. write version V+1 with check-and-set cas=V: the rotated key gets a new
     value, every other key keeps its value;
  5. apply the hook on the server and verify it (a login with the new value,
     or the client secret read back);
  6. on a failure in 5: undo on the server (best effort, as far as it got),
     then restore the previous data as version V+2 (cas=V+1).

Hooks (plan "hook"):
  postgres-alter-user  ALTER ROLE <user> PASSWORD '<SCRAM-SHA-256 verifier>'
                       as <user> itself (the password never reaches the server
                       in clear text, so no server log can hold it); Postgres
                       wire protocol v3, SCRAM-SHA-256 / MD5 / cleartext
                       authentication, no TLS (the in-cluster services serve none)
  redis-acl-set        ACL SETUSER <user> resetpass #<sha256 of the new value>
                       after AUTH <user> <current value> (RESP)
  keycloak-client-secret-set
                       the admin REST API: token from realm master (admin-cli,
                       password grant; the admin password from the platform
                       Secret, read through the Kubernetes API), then PUT
                       {"secret"} on the client; undo restores the secret
                       Keycloak held before (read in the precheck)
  operator-write       no write, no hook

Inputs, all non-secret:
  BAO_ADDR, BAO_CACERT     OpenBao API address and CA bundle (ca.crt only)
  BAO_CLIENT_TIMEOUT       per-request timeout ("15s" or seconds)
  OB_AUTH_MOUNT, OB_ROLE   Kubernetes auth mount and role
  OB_JWT_FILE              projected ServiceAccount token (OpenBao audience)
  OB_PLAN_FILE             plan.json:
                             {"mount", "id", "path" (relative to the mount),
                              "hook", "keys": [every KV key of the entry],
                              "rotate": {<kv_key>: {"type": "password", "length", "special"}
                                                   | {"type": "hex", "bytes"}},
                              "target": {hook fields}, "timeout": seconds,
                              "keycloak": {"url", "admin_user",
                                           "admin_secret": {"namespace", "name", "key"}}}
  KUBE_API, KUBE_CACERT    Kubernetes API address and CA (kube-root-ca.crt);
  KUBE_TOKEN_FILE          projected ServiceAccount token (API audience);
                           read only by the Keycloak hook

Secrets: the current and new values, the Keycloak admin password and token
and the OpenBao token live only in this process. They are never printed,
logged, written to a file or put in argv or env; every error text is scrubbed
of them before it is printed. No proxy is used.

Output (stdout): one line per result, "ERAG_SECRETS_RESULT <json>":
  {"kind":"probe","state":"ok|unreachable|uninitialized|sealed|login_failed","error":"..."}
  {"kind":"credential","id":"...","action":"rotate","hook":"...",
   "result":"rotated|operator|precheck_failed|rolled_back|restore_failed|missing|deleted|incomplete|error",
   "version":N,"previous_version":V,"server":"changed|unchanged|restored|unknown","error":"..."}
     version: the current KV version after the run (rotated: V+1,
     rolled_back: V+2 holding version V's data, restore_failed: V+1).
     server: what the hook left on the server.
  {"kind":"stage","id":"...","stage":"written","version":V+1,"previous_version":V}
     printed right after the new version is written, so a Job that dies
     before its result line still tells the adapter what OpenBao holds.
  {"kind":"done","state":"ok|failed","error":"..."}   (always last)
Exit: 0 when the result is rotated or operator. Any failure after the write,
of whatever kind, runs the undo and the restore.
"""

import base64
import hashlib
import hmac
import json
import os
import secrets
import socket
import ssl
import string
import struct
import sys
import urllib.error
import urllib.parse
import urllib.request

PREFIX = "ERAG_SECRETS_RESULT "
SPECIAL = "!#%+,.:=@^_~-"
HOOKS = ("operator-write", "postgres-alter-user", "redis-acl-set", "keycloak-client-secret-set")


def result(obj):
    sys.stdout.write(PREFIX + json.dumps(obj, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def log(msg):
    sys.stderr.write("erag-secrets-rotator: %s\n" % msg)
    sys.stderr.flush()


class RunError(Exception):
    """Stops the run; the message never holds a value (and is scrubbed)."""


class HookError(Exception):
    """A server step failed; the message is scrubbed before it is printed."""


# Every secret string of the run; scrub() replaces each in any text it prints.
SENSITIVE = set()


def sensitive(*values):
    for v in values:
        if isinstance(v, str) and len(v) >= 4:
            SENSITIVE.add(v)
    return values[0] if len(values) == 1 else values


def scrub(text):
    text = str(text)
    for v in sorted(SENSITIVE, key=len, reverse=True):
        text = text.replace(v, "***")
    return text[:400]


def timeout_seconds(text):
    text = str(text or "15s").strip().removesuffix("s")
    try:
        return max(1, int(text))
    except ValueError:
        return 15


def read_file(path, what):
    try:
        with open(path, encoding="utf-8") as handle:
            return handle.read().strip()
    except OSError as err:
        raise RunError("cannot read %s (%s): %s" % (what, path, err.strerror)) from None


class Http:
    """JSON (or form) over HTTP(S) with an optional CA file and no proxy."""

    def __init__(self, base, cafile, timeout):
        self.base = base.rstrip("/")
        handlers = [urllib.request.ProxyHandler({})]
        if self.base.startswith("https://"):
            ctx = ssl.create_default_context(cafile=cafile) if cafile else ssl.create_default_context()
            handlers.append(urllib.request.HTTPSHandler(context=ctx))
        self.opener = urllib.request.build_opener(*handlers)
        self.timeout = timeout

    def call(self, method, path, body=None, headers=None, form=None, content_type="application/json"):
        """Returns (status, parsed JSON (dict or list) or {}); status 0 = no HTTP answer."""
        if form is not None:
            data = urllib.parse.urlencode(form).encode()
            content_type = "application/x-www-form-urlencoded"
        else:
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
        data = None
        try:
            doc = json.loads(raw) if raw else {}
        except ValueError:
            doc = {}
        raw = None
        return status, doc if isinstance(doc, (dict, list)) else {}


def errors_of(doc):
    """OpenBao {"errors"}, Kubernetes Status message or Keycloak error text (scrubbed)."""
    if isinstance(doc, dict):
        for key in ("errors", "message", "errorMessage", "error_description", "error"):
            v = doc.get(key)
            if v:
                return scrub("; ".join(str(e) for e in v) if isinstance(v, list) else v)[:300]
    return ""


def generate(spec):
    """A new value for a password or hex spec."""
    if spec.get("type") == "hex":
        n = int(spec.get("bytes", 0))
        if not 8 <= n <= 128:
            raise RunError("hex bytes must be 8..128")
        return secrets.token_hex(n)
    if spec.get("type") != "password":
        raise RunError("unsupported generator for rotation: %s" % spec.get("type"))
    length = int(spec.get("length", 0))
    if not 8 <= length <= 256:
        raise RunError("password length must be 8..256")
    special = bool(spec.get("special"))
    alphabet = string.ascii_letters + string.digits + (SPECIAL if special else "")
    for _ in range(100):
        value = "".join(secrets.choice(alphabet) for _ in range(length))
        if not special:
            return value
        if (any(c.isdigit() for c in value) and any(c.isupper() for c in value)
                and any(c.islower() for c in value) and any(c in SPECIAL for c in value)):
            return value
    raise RunError("password generation failed")


# --- Postgres ---------------------------------------------------------------------------


def scram_verifier(password, iterations=4096):
    """The SCRAM-SHA-256 verifier Postgres stores (ALTER ROLE accepts it as the password)."""
    salt = os.urandom(16)
    salted = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    client_key = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
    stored_key = hashlib.sha256(client_key).digest()
    server_key = hmac.new(salted, b"Server Key", hashlib.sha256).digest()
    b64 = base64.b64encode
    return sensitive("SCRAM-SHA-256$%d:%s$%s:%s" % (iterations, b64(salt).decode(), b64(stored_key).decode(),
                                                     b64(server_key).decode()))


class Postgres:
    """The few protocol v3 messages a login and one simple query need."""

    def __init__(self, host, port, user, password, database, timeout):
        self.user, self.password = user, password
        try:
            self.sock = socket.create_connection((host, int(port)), timeout=timeout)
        except OSError as err:
            raise HookError("connect to %s:%s: %s" % (host, port, err.strerror or type(err).__name__)) from None
        self.sock.settimeout(timeout)
        try:
            params = b"user\0" + user.encode() + b"\0database\0" + database.encode() + b"\0\0"
            self.sock.sendall(struct.pack("!ii", 8 + len(params), 196608) + params)
            self.login()
        except BaseException:
            self.close()
            raise

    def close(self):
        try:
            self.sock.sendall(b"X\0\0\0\4")
        except OSError:
            pass
        self.sock.close()

    def recv(self, n):
        buf = b""
        while len(buf) < n:
            try:
                chunk = self.sock.recv(n - len(buf))
            except OSError as err:
                raise HookError("postgres: %s" % (err.strerror or type(err).__name__)) from None
            if not chunk:
                raise HookError("postgres closed the connection")
            buf += chunk
        return buf

    def message(self):
        kind = self.recv(1)
        (length,) = struct.unpack("!i", self.recv(4))
        if not 4 <= length <= 1 << 24:
            raise HookError("postgres: bad message length")
        return kind, self.recv(length - 4)

    def send(self, kind, payload):
        self.sock.sendall(kind + struct.pack("!i", len(payload) + 4) + payload)

    @staticmethod
    def error_text(payload):
        fields = {}
        for part in payload.split(b"\0"):
            if part:
                fields[chr(part[0])] = part[1:].decode("utf-8", "replace")
        return scrub("%s %s: %s" % (fields.get("S", "ERROR"), fields.get("C", ""), fields.get("M", "")))

    def login(self):
        nonce = client_first = salted = auth_message = None
        while True:
            kind, payload = self.message()
            if kind == b"E":
                raise HookError("postgres login as %s: %s" % (self.user, self.error_text(payload)))
            if kind == b"Z":
                return
            if kind != b"R":
                continue
            (code,) = struct.unpack("!i", payload[:4])
            if code == 0:
                continue
            if code == 3:
                self.send(b"p", self.password.encode() + b"\0")
            elif code == 5:
                inner = hashlib.md5((self.password + self.user).encode()).hexdigest()
                self.send(b"p", b"md5" + hashlib.md5(inner.encode() + payload[4:8]).hexdigest().encode() + b"\0")
            elif code == 10:
                mechanisms = payload[4:].split(b"\0")
                if b"SCRAM-SHA-256" not in mechanisms:
                    raise HookError("postgres offers no SCRAM-SHA-256")
                nonce = base64.b64encode(os.urandom(18)).decode()
                client_first = "n=,r=" + nonce
                first = ("n,," + client_first).encode()
                self.send(b"p", b"SCRAM-SHA-256\0" + struct.pack("!i", len(first)) + first)
            elif code == 11:
                server_first = payload[4:].decode()
                attrs = dict(a.split("=", 1) for a in server_first.split(",") if "=" in a)
                if not attrs.get("r", "").startswith(nonce or "\0"):
                    raise HookError("postgres SCRAM: bad server nonce")
                salted = hashlib.pbkdf2_hmac("sha256", self.password.encode("utf-8"),
                                             base64.b64decode(attrs["s"]), int(attrs["i"]))
                without_proof = "c=biws,r=" + attrs["r"]
                auth_message = f"{client_first},{server_first},{without_proof}".encode()
                client_key = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
                signature = hmac.new(hashlib.sha256(client_key).digest(), auth_message, hashlib.sha256).digest()
                proof = bytes(a ^ b for a, b in zip(client_key, signature))
                self.send(b"p", (without_proof + ",p=" + base64.b64encode(proof).decode()).encode())
            elif code == 12:
                server_key = hmac.new(salted, b"Server Key", hashlib.sha256).digest()
                expected = base64.b64encode(hmac.new(server_key, auth_message, hashlib.sha256).digest()).decode()
                if payload[4:].decode() != "v=" + expected:
                    raise HookError("postgres SCRAM: the server signature does not match")
            else:
                raise HookError("postgres asks for unsupported authentication %d" % code)

    def query(self, sql):
        self.send(b"Q", sql.encode() + b"\0")
        err = None
        while True:
            kind, payload = self.message()
            if kind == b"E":
                err = self.error_text(payload)
            elif kind == b"Z":
                break
        if err:
            raise HookError("postgres: %s" % err)


def quote_ident(name):
    return '"' + name.replace('"', '""') + '"'


class PostgresHook:
    def __init__(self, target, timeout):
        self.t, self.timeout = target, timeout
        for k in ("host", "port", "database", "user"):
            if not str(target.get(k, "")):
                raise RunError("postgres-alter-user: target.%s is empty" % k)

    def connect(self, password):
        t = self.t
        return Postgres(t["host"], t["port"], str(t["user"]), password, str(t["database"]), self.timeout)

    def login_works(self, password):
        self.connect(password).close()

    def set_password(self, login_password, new_password):
        conn = self.connect(login_password)
        try:
            conn.query("ALTER ROLE %s PASSWORD '%s'" % (quote_ident(str(self.t["user"])), scram_verifier(new_password)))
        finally:
            conn.close()

    def precheck(self, old):
        self.login_works(old)

    def apply(self, old, new):
        self.set_password(old, new)

    def verify(self, new):
        self.login_works(new)

    def undo(self, old, new):
        """True when the server holds the old value again (or never changed)."""
        try:
            self.set_password(new, old)
        except HookError:
            pass
        try:
            self.login_works(old)
            return True
        except HookError:
            return False


# --- Redis ------------------------------------------------------------------------------


class Redis:
    def __init__(self, host, port, timeout):
        try:
            self.sock = socket.create_connection((host, int(port)), timeout=timeout)
        except OSError as err:
            raise HookError("connect to %s:%s: %s" % (host, port, err.strerror or type(err).__name__)) from None
        self.sock.settimeout(timeout)
        self.buf = b""

    def close(self):
        self.sock.close()

    def fill(self):
        try:
            chunk = self.sock.recv(4096)
        except OSError as err:
            raise HookError("redis: %s" % (err.strerror or type(err).__name__)) from None
        if not chunk:
            raise HookError("redis closed the connection")
        self.buf += chunk
        if len(self.buf) > 1 << 20:
            raise HookError("redis: reply too long")

    def line(self):
        while b"\r\n" not in self.buf:
            self.fill()
        out, self.buf = self.buf.split(b"\r\n", 1)
        return out

    def reply(self):
        head = self.line()
        kind, rest = head[:1], head[1:].decode("utf-8", "replace")
        if kind == b"-":
            raise HookError("redis: %s" % scrub(rest))
        if kind in (b"+", b":"):
            return rest
        if kind == b"$":
            n = int(rest)
            if n < 0:
                return None
            while len(self.buf) < n + 2:
                self.fill()
            out, self.buf = self.buf[:n], self.buf[n + 2:]
            return out.decode("utf-8", "replace")
        if kind == b"*":
            return [self.reply() for _ in range(max(0, int(rest)))]
        raise HookError("redis: unexpected reply")

    def command(self, *args):
        parts = [b"*%d\r\n" % len(args)]
        for a in args:
            data = str(a).encode()
            parts.append(b"$%d\r\n%s\r\n" % (len(data), data))
        try:
            self.sock.sendall(b"".join(parts))
        except OSError as err:
            raise HookError("redis: %s" % (err.strerror or type(err).__name__)) from None
        return self.reply()


class RedisHook:
    def __init__(self, target, timeout):
        self.t, self.timeout = target, timeout
        for k in ("host", "port", "user"):
            if not str(target.get(k, "")):
                raise RunError("redis-acl-set: target.%s is empty" % k)

    def session(self, password):
        conn = Redis(self.t["host"], self.t["port"], self.timeout)
        try:
            conn.command("AUTH", str(self.t["user"]), password)
            if conn.command("PING") != "PONG":
                raise HookError("redis: PING did not answer PONG")
        except BaseException:
            conn.close()
            raise
        return conn

    def login_works(self, password):
        self.session(password).close()

    def set_password(self, login_password, new_password):
        conn = self.session(login_password)
        try:
            digest = sensitive(hashlib.sha256(new_password.encode()).hexdigest())
            conn.command("ACL", "SETUSER", str(self.t["user"]), "resetpass", "#" + digest)
        finally:
            conn.close()

    def precheck(self, old):
        self.login_works(old)

    def apply(self, old, new):
        self.set_password(old, new)

    def verify(self, new):
        self.login_works(new)

    def undo(self, old, new):
        try:
            self.set_password(new, old)
        except HookError:
            pass
        try:
            self.login_works(old)
            return True
        except HookError:
            return False


# --- Keycloak ---------------------------------------------------------------------------


class KeycloakHook:
    def __init__(self, target, timeout, settings, kube):
        self.t, self.settings, self.kube = target, settings, kube
        for k in ("realm", "client_id"):
            if not str(target.get(k, "")):
                raise RunError("keycloak-client-secret-set: target.%s is empty" % k)
        if not settings.get("url"):
            raise RunError("keycloak-client-secret-set: no Keycloak URL in the plan")
        self.http = Http(settings["url"], None, timeout)
        self.uuid = None
        self.before = None
        self.admin_password = None

    def token(self):
        if self.admin_password is None:
            self.admin_password = sensitive(self.kube.secret_value(self.settings["admin_secret"]))
        status, doc = self.http.call("POST", "/realms/master/protocol/openid-connect/token", form={
            "grant_type": "password", "client_id": "admin-cli",
            "username": self.settings.get("admin_user", "admin"), "password": self.admin_password})
        token = doc.get("access_token") if status == 200 and isinstance(doc, dict) else None
        if not token:
            raise HookError("keycloak admin login at %s (realm master, user %s): %s %s" % (
                self.http.base, self.settings.get("admin_user", "admin"), status, errors_of(doc)))
        return {"Authorization": "Bearer " + sensitive(token)}

    def client_path(self, suffix=""):
        return "/admin/realms/%s/clients/%s%s" % (urllib.parse.quote(str(self.t["realm"]), safe=""),
                                                  urllib.parse.quote(self.uuid, safe=""), suffix)

    def find(self, auth):
        realm = urllib.parse.quote(str(self.t["realm"]), safe="")
        status, doc = self.http.call("GET", "/admin/realms/%s/clients?clientId=%s" % (
            realm, urllib.parse.quote(str(self.t["client_id"]), safe="")), headers=auth)
        if status != 200 or not isinstance(doc, list):
            raise HookError("keycloak: list clients of realm %s: %s %s" % (self.t["realm"], status, errors_of(doc)))
        match = [c for c in doc if isinstance(c, dict) and c.get("clientId") == str(self.t["client_id"])]
        if len(match) != 1 or not match[0].get("id"):
            raise HookError("keycloak: realm %s has no client %s" % (self.t["realm"], self.t["client_id"]))
        self.uuid = match[0]["id"]

    def current(self, auth):
        status, doc = self.http.call("GET", self.client_path("/client-secret"), headers=auth)
        value = doc.get("value") if status == 200 and isinstance(doc, dict) else None
        if not value:
            raise HookError("keycloak: read the secret of client %s: %s %s" % (self.t["client_id"], status,
                                                                               errors_of(doc)))
        return sensitive(value)

    def put(self, auth, value):
        status, doc = self.http.call("PUT", self.client_path(), {"secret": value}, headers=auth)
        if status not in (200, 204):
            raise HookError("keycloak: set the secret of client %s: %s %s" % (self.t["client_id"], status,
                                                                              errors_of(doc)))

    def precheck(self, old):
        auth = self.token()
        self.find(auth)
        self.before = self.current(auth)
        if self.before != old:
            log("Keycloak held another secret for %s than OpenBao; rotation sets both" % self.t["client_id"])

    def apply(self, old, new):
        self.put(self.token(), new)

    def verify(self, new):
        if self.current(self.token()) != new:
            raise HookError("keycloak: client %s does not hold the new secret after the update" % self.t["client_id"])

    def undo(self, old, new):
        try:
            auth = self.token()
            self.put(auth, self.before)
            return self.current(auth) == self.before
        except HookError:
            return False


# --- the run ----------------------------------------------------------------------------


class Kube:
    def __init__(self, env, timeout):
        api = env.get("KUBE_API", "https://kubernetes.default.svc")
        if not api.startswith("https://"):
            raise RunError("KUBE_API must be an https:// URL")
        self.http = Http(api, env.get("KUBE_CACERT") or None, timeout)
        self.token_file = env.get("KUBE_TOKEN_FILE", "")

    def secret_value(self, ref):
        token = read_file(self.token_file, "KUBE_TOKEN_FILE")
        status, doc = self.http.call("GET", "/api/v1/namespaces/%s/secrets/%s" % (
            urllib.parse.quote(ref["namespace"], safe=""), urllib.parse.quote(ref["name"], safe="")),
            headers={"Authorization": "Bearer " + token})
        token = None
        raw = ((doc.get("data") or {}).get(ref["key"]) if status == 200 and isinstance(doc, dict) else None)
        if not raw:
            raise HookError("read Secret %s/%s key %s: %s %s" % (ref["namespace"], ref["name"], ref["key"], status,
                                                                errors_of(doc)))
        try:
            return base64.b64decode(raw, validate=True).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            raise HookError("Secret %s/%s key %s is not UTF-8 text" % (ref["namespace"], ref["name"],
                                                                     ref["key"])) from None


class Rotator:
    def __init__(self, env):
        self.env = env
        timeout = timeout_seconds(env.get("BAO_CLIENT_TIMEOUT"))
        addr = env.get("BAO_ADDR", "")
        if not addr.startswith("https://"):
            raise RunError("BAO_ADDR must be an https:// URL")
        self.bao = Http(addr, env.get("BAO_CACERT") or None, timeout)
        self.plan = json.loads(read_file(env.get("OB_PLAN_FILE", ""), "OB_PLAN_FILE"))
        for k in ("mount", "id", "path", "hook", "keys"):
            if not self.plan.get(k):
                raise RunError("the plan has no %s" % k)
        if self.plan["hook"] not in HOOKS:
            raise RunError("unknown hook %s" % self.plan["hook"])
        self.mount = self.plan["mount"]
        self.token = None
        self.hook_timeout = int(self.plan.get("timeout") or 15)
        self.kube_timeout = timeout

    def report(self, res, version, previous, server, error=""):
        result({"kind": "credential", "id": self.plan["id"], "action": "rotate", "hook": self.plan["hook"],
                "result": res, "version": version, "previous_version": previous, "server": server,
                "error": scrub(error)})

    # --- OpenBao ---

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
        self.token = sensitive(token)
        result({"kind": "probe", "state": "ok", "error": ""})

    def kv(self, method, body=None):
        return self.bao.call(method, "/v1/%s/data/%s" % (self.mount, urllib.parse.quote(self.plan["path"])), body,
                             {"X-Vault-Token": self.token})

    def revoke(self):
        if self.token:
            status, _ = self.bao.call("POST", "/v1/auth/token/revoke-self", {}, {"X-Vault-Token": self.token})
            if status not in (200, 204):
                log("token revoke failed (%s)" % status)
            self.token = None

    def read_current(self):
        """(version, data) of the live current version, or reports and returns None."""
        status, doc = self.kv("GET")
        meta = ((doc.get("data") or {}).get("metadata") or {}) if isinstance(doc, dict) else {}
        version = meta.get("version") or 0
        data = (doc.get("data") or {}).get("data") if status == 200 else None
        where = "%s/%s" % (self.mount, self.plan["path"])
        if status == 404 and not version:
            self.report("missing", 0, 0, "unchanged", "%s does not exist (%s)" % (
                where, "the operator writes it first: bao kv put -mount=%s %s ..." % (self.mount, self.plan["path"])
                if self.plan["hook"] == "operator-write" else "run a normal install first"))
            return None
        if data is None:
            if status == 404:
                self.report("deleted", version, version, "unchanged", "the current version of %s is deleted or "
                            "destroyed; restore it (bao kv undelete) or, when it is destroyed, write a new version "
                            "the server accepts (bao kv rollback -version=<an older version>) first" % where)
            else:
                self.report("error", version, version, "unchanged", "read %s: %s" % (where, errors_of(doc) or status))
            return None
        sensitive(*[v for v in data.values() if isinstance(v, str)])
        lacking = [k for k in self.plan["keys"] if not isinstance(data.get(k), str) or not data.get(k)]
        if lacking:
            self.report("incomplete", version, version, "unchanged", "%s lacks key(s) %s" % (where, " ".join(lacking)))
            return None
        return version, data

    def write(self, data, cas):
        status, doc = self.kv("POST", {"options": {"cas": cas}, "data": data})
        if status in (200, 204):
            return ((doc.get("data") or {}).get("version")) or 0, ""
        return 0, "write %s/%s (cas=%d): %s" % (self.mount, self.plan["path"], cas, errors_of(doc) or status)

    # --- the rotation ---

    def hook(self):
        target = self.plan.get("target") or {}
        name = self.plan["hook"]
        if name == "postgres-alter-user":
            return PostgresHook(target, self.hook_timeout)
        if name == "redis-acl-set":
            return RedisHook(target, self.hook_timeout)
        settings = self.plan.get("keycloak") or {}
        return KeycloakHook(target, self.hook_timeout, settings, Kube(self.env, self.kube_timeout))

    def run(self):
        self.probe()
        current = self.read_current()
        if current is None:
            raise RunError("the KV entry cannot be rotated")
        version, old_data = current
        if self.plan["hook"] == "operator-write":
            old_data = None
            self.report("operator", version, version, "unchanged")
            return
        rotate = self.plan.get("rotate") or {}
        if len(rotate) != 1:
            raise RunError("the plan must rotate exactly one key")
        ((key, spec),) = rotate.items()
        if key not in self.plan["keys"]:
            raise RunError("the rotated key %s is not a key of the entry" % key)
        hook = self.hook()
        old = old_data[key]
        try:
            hook.precheck(old)
        except Exception as err:  # noqa: BLE001 (any failure before the write changes nothing)
            err = err if isinstance(err, HookError) else "unexpected %s" % type(err).__name__
            self.report("precheck_failed", version, version, "unchanged",
                        "%s precheck with the current value failed, nothing changed: %s" % (self.plan["hook"], err))
            raise RunError("precheck failed") from None
        new = sensitive(generate(spec))
        new_data = dict(old_data)
        new_data[key] = new
        written, err = self.write(new_data, version)
        if not written:
            self.report("error", version, version, "unchanged", err + "; nothing changed")
            raise RunError("write failed")
        new_data = None
        # If the Job dies from here on (deadline, node loss), the adapter knows
        # that OpenBao holds an unapplied new version (no value in this line).
        result({"kind": "stage", "id": self.plan["id"], "stage": "written", "version": written,
                "previous_version": version})
        try:
            hook.apply(old, new)
            hook.verify(new)
        except Exception as caught:  # noqa: BLE001 (every failure after the write rolls back)
            hook_err = caught if isinstance(caught, HookError) else "unexpected %s" % type(caught).__name__
            try:
                restored_server = hook.undo(old, new)
            except Exception:  # noqa: BLE001
                restored_server = False
            server = "restored" if restored_server else "unknown"
            back, werr = self.write(old_data, written)
            if back:
                self.report("rolled_back", back, version, server,
                            "%s failed: %s. Version %d (the new value) was written, then version %d restores "
                            "version %d%s" % (self.plan["hook"], hook_err, written, back, version,
                                              "" if restored_server else
                                              "; the server may still hold the new value (check it by hand)"))
            else:
                self.report("restore_failed", written, version, server,
                            "%s failed: %s. Restoring version %d also failed (%s): OpenBao holds the new value "
                            "(version %d) and the server %s. Restore by hand: bao kv rollback -mount=%s "
                            "-version=%d %s" % (self.plan["hook"], hook_err, version, werr, written,
                                                "holds the old value again" if restored_server
                                                else "may hold either value", self.mount, version,
                                                self.plan["path"]))
            raise RunError("hook failed") from None
        finally:
            old_data = None
        self.report("rotated", written, version, "changed")


def main():
    rotator = None
    try:
        rotator = Rotator(os.environ)
        rotator.run()
    except RunError as err:
        log(scrub(err))
        if rotator:
            rotator.revoke()
        result({"kind": "done", "state": "failed", "error": scrub(err)})
        return 1
    except Exception as err:  # noqa: BLE001 (report any crash without a traceback, which could hold data)
        log("unexpected %s" % type(err).__name__)
        if rotator:
            rotator.revoke()
        result({"kind": "done", "state": "failed", "error": "unexpected %s" % type(err).__name__})
        return 1
    rotator.revoke()
    result({"kind": "done", "state": "ok", "error": ""})
    return 0


if __name__ == "__main__":
    sys.exit(main())
