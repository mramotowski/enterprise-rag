#!/usr/bin/env python3
# Copyright (C) 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0
"""app_secrets openbao adapter: the in-cluster secrets Job (AD-3).

Runs as the only container of an erag-secrets Job (python:3.12-slim, standard
library only), rendered from templates/secrets-job.yaml.j2, and in the tests
(tests/files/fake_openbao_cluster.py runs it on the test host).

    python3 -I secrets_job.py <probe|ensure|status|delete|import|rotate>

Every op starts with the probe: OpenBao reachable, initialized and unsealed
(sys/health), then a Kubernetes-auth login as OB_ROLE. Then:
  ensure  for every plan entry:
            write  create the KV v2 entry with cas=0 when it does not exist (CAS
                   mismatch = created meanwhile = exists); an existing entry
                   must have every key of the entry
            check  existence and current version; with keys, an existing entry
                   must also have every key
  status  "check" for every entry (status plans carry no keys: metadata only)
  delete  for every entry: delete the metadata and every version, then read it
          back (it must be gone); then, with "purge" (teardown of a whole
          layer, skipped when a delete failed), delete every entry left under
          <cluster_id>/<layer>/ and list the prefix again (it must be empty)
  import  (migration, AD-12, role erag-secrets-importer) read every legacy
          Secret of the plan (Kubernetes API); check each entry (every KV key
          has a value, the sources of one key agree); compare with OpenBao (the
          same value is "exists", another one a "conflict": nothing is written);
          write the others with cas=0; then (only when all that worked) hand the
          Helm-managed Secrets to ESO (helm.sh/resource-policy: keep) and remove
          the local markup
  rotate  (AD-9, one credential) read the live current version V (it must hold
          every key; operator-write stops here), precheck the current value on
          the server, write V+1 with cas=V (the rotated key gets a new value),
          apply the hook and verify it; on a failure after the write undo on
          the server (best effort) and restore V's data as V+2 (cas=V+1).
          Hooks: postgres-alter-user (ALTER ROLE ... PASSWORD '<SCRAM verifier>'
          as the user itself, wire protocol v3, no TLS), redis-acl-set (AUTH,
          then ACL SETUSER <user> resetpass #<sha256>), keycloak-client-secret-set
          (admin REST API; the admin password from the platform Secret through
          the Kubernetes API; undo restores the secret Keycloak held before),
          operator-write (no write, no hook)

Inputs, all non-secret:
  argv                     the op name only
  BAO_ADDR, BAO_CACERT     OpenBao API address and CA bundle (ca.crt only)
  BAO_CLIENT_TIMEOUT       per-request timeout ("15s" or seconds)
  OB_AUTH_MOUNT, OB_ROLE   Kubernetes auth mount and role
  OB_JWT_FILE              projected ServiceAccount token (OpenBao audience)
  OB_PLAN_FILE             plan.json, {"mount": <kv mount>, ...}; paths are
                           relative to the mount (<cluster_id>/<layer>/...):
    ensure/status/delete   "entries": [{"action": "write|check|delete", "id", "path",
                                        "keys": {<kv_key>: <spec>}}], "purge": "<cid>/<layer>"
                           spec: {"type": "password", "length", "special"} | {"type": "hex", "bytes"}
                                 | {"type": "nkey_user", "writes": [<seed key>, <public key key>]}
                                 | {"type": "static"} (operator-supplied: never generated)
    import                 "entries": [{"id", "path", "required",
                                        "keys": {<kv_key>: [{"namespace", "name", "key"}]}}],
                           "handover"/"unmark": [{"namespace", "name"}],
                           "markup_label", "markup_annotation"
    rotate                 "id", "path", "hook", "keys": [every KV key], "rotate": {<kv_key>: <spec>},
                           "target": {hook fields}, "timeout",
                           "keycloak": {"url", "admin_user", "admin_secret": {"namespace", "name", "key"}}
  KUBE_API, KUBE_CACERT    Kubernetes API address and CA (import, Keycloak hook)
  KUBE_TOKEN_FILE          projected ServiceAccount token (API audience)

Secrets: generated, legacy, current and new values, the Keycloak admin password
and token and the OpenBao token live only in this process. They are never
printed, logged, written to a file or put in argv or env; every error text is
scrubbed of them. No proxy is used. NKey pairs (nats-io/nkeys): a random 32-byte
ed25519 seed, the public key derived here (RFC 8032).

Output (stdout): one line per result, "ERAG_SECRETS_RESULT <json>":
  {"kind":"probe","state":"ok|unreachable|uninitialized|sealed|login_failed","error":"..."}
  {"kind":"credential","id","action":"write|check|delete","version":N,"error",
   "result":"created|exists|missing|deleted|incomplete|removed|error"}
     incomplete: the entry lacks keys of the plan (added to the registry later);
     delete: removed (an entry was there, now gone) or missing (none was there)
  {"kind":"purge","prefix","state":"ok|error","removed":N,"error"}
  {"kind":"legacy","found":N,"error":""}      import: legacy Secrets found
  {"kind":"credential","id","action":"import","version":N,"error",
   "result":"created|exists|conflict|absent|missing|error"}
     absent: no legacy value (ensure generates it); missing: none, but required
  {"kind":"secret","namespace","name","action":"keep|unmark","error",
   "result":"patched|unchanged|skipped|missing|error"}
  {"kind":"credential","id","action":"rotate","hook","version":N,"previous_version":V,
   "result":"rotated|operator|precheck_failed|rolled_back|restore_failed|missing|deleted|incomplete|error",
   "server":"changed|unchanged|restored|unknown","error"}
  {"kind":"stage","id","stage":"written","version":V+1,"previous_version":V}
     rotate: right after the write, so a Job that dies still tells what OpenBao holds
  {"kind":"done","state":"ok|failed","error":"..."}   (always last)
Exit: 0 when every result is a success of its op, 1 otherwise.
"""

import base64
import datetime
import hashlib
import hmac
import json
import os
import re
import secrets
import signal
import socket
import ssl
import string
import struct
import sys
import urllib.error
import urllib.parse
import urllib.request

PREFIX = "ERAG_SECRETS_RESULT "
OPS = ("probe", "ensure", "status", "delete", "import", "rotate")
SPECIAL = "!#%+,.:=@^_~-"
HOOKS = ("operator-write", "postgres-alter-user", "redis-acl-set", "keycloak-client-secret-set")
KEEP = "helm.sh/resource-policy"
HELM_LABEL = "app.kubernetes.io/managed-by"
PURGE_MAX = 10000
SEGMENT = re.compile(r"[A-Za-z0-9._-]+")
CRED_ID = re.compile(r"[a-z0-9-]+/[a-z0-9-]+")
KV_KEY = re.compile(r"[a-z][a-z0-9_]*")


def result(obj):
    sys.stdout.write(PREFIX + json.dumps(obj, separators=(",", ":")) + "\n")
    sys.stdout.flush()


def log(msg):
    sys.stderr.write("erag-secrets-job: %s\n" % msg)
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
    """Seconds of a Go duration of h/m/s ("15s", "1m30s") or a bare number."""
    text = str(text or "15s").strip()
    match = re.fullmatch(r"(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?", text) if not text.isdigit() else None
    if text.isdigit():
        seconds = int(text)
    elif match and any(match.groups()):
        h, m, sec = (int(g or 0) for g in match.groups())
        seconds = h * 3600 + m * 60 + sec
    else:
        raise RunError("BAO_CLIENT_TIMEOUT %r is not a duration (e.g. 15s, 1m30s)" % text[:40])
    return max(1, seconds)


def read_file(path, what):
    try:
        with open(path, encoding="utf-8") as handle:
            return handle.read().strip()
    except OSError as err:
        raise RunError("cannot read %s (%s): %s" % (what, path, err.strerror)) from None


def is_segment(text):
    return isinstance(text, str) and bool(SEGMENT.fullmatch(text)) and text not in (".", "..")


def is_kv_path(text):
    return isinstance(text, str) and all(is_segment(s) for s in text.split("/"))


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


class ApiHttp(Http):
    """OpenBao and Kubernetes API: every answer is a JSON object ({} otherwise)."""

    def call(self, *args, **kwargs):
        status, doc = super().call(*args, **kwargs)
        return status, doc if isinstance(doc, dict) else {}


def errors_of(doc):
    """OpenBao {"errors"}, Kubernetes Status message or Keycloak error text (scrubbed)."""
    if isinstance(doc, dict):
        for key in ("errors", "message", "errorMessage", "error_description", "error"):
            v = doc.get(key)
            if v:
                return scrub("; ".join(str(e) for e in v) if isinstance(v, list) else v)[:300]
    return ""


# --- generators -------------------------------------------------------------------------


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
    # With special, the value holds at least one digit, upper-case, lower-case
    # and special character (password policies such as the Keycloak realm's).
    for _ in range(100):
        value = "".join(secrets.choice(alphabet) for _ in range(length))
        if not special:
            return value
        if (any(c.isdigit() for c in value) and any(c.isupper() for c in value)
                and any(c.islower() for c in value) and any(c in SPECIAL for c in value)):
            return value
    raise RunError("password generation failed")


# Ed25519 (RFC 8032 5.1): the public key of a 32-byte seed. Key generation only,
# in a short-lived pod: nothing is signed, so timing does not matter here.
ED_P = 2**255 - 19
ED_D = -121665 * pow(121666, ED_P - 2, ED_P) % ED_P
ED_B = (15112221349535400772501151409588531511454012693041857206046113283949847762202,
        46316835694926478169428394003475163141307993866256225615783033603165251855960)


def ed_add(p, q):
    """Extended homogeneous coordinates (X, Y, Z, T), RFC 8032 5.1.4."""
    a = (p[1] - p[0]) * (q[1] - q[0]) % ED_P
    b = (p[1] + p[0]) * (q[1] + q[0]) % ED_P
    c = 2 * p[3] * q[3] * ED_D % ED_P
    d = 2 * p[2] * q[2] % ED_P
    e, f, g, h = b - a, d - c, d + c, b + a
    return e * f % ED_P, g * h % ED_P, f * g % ED_P, e * h % ED_P


def ed25519_public(seed):
    digest = hashlib.sha512(seed).digest()
    a = int.from_bytes(digest[:32], "little")
    a = (a & ((1 << 254) - 8)) | (1 << 254)
    point, acc = (ED_B[0], ED_B[1], 1, ED_B[0] * ED_B[1] % ED_P), (0, 1, 1, 0)
    while a:
        if a & 1:
            acc = ed_add(acc, point)
        point = ed_add(point, point)
        a >>= 1
    zinv = pow(acc[2], ED_P - 2, ED_P)
    x, y = acc[0] * zinv % ED_P, acc[1] * zinv % ED_P
    return (y | (x & 1) << 255).to_bytes(32, "little")


def nkey_encode(prefix, payload):
    """nats-io/nkeys: prefix + payload + CRC-16/XMODEM (little-endian), base32 without padding."""
    raw = prefix + payload
    crc = 0
    for byte in raw:
        crc ^= byte << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021 if crc & 0x8000 else crc << 1) & 0xFFFF
    return base64.b32encode(raw + struct.pack("<H", crc)).decode().rstrip("=")


def nkey_user():
    """(seed SU..., public key U...) of a new NATS user NKey."""
    seed = secrets.token_bytes(32)
    # Seed prefix: PREFIX_BYTE_SEED (18<<3) | PREFIX_BYTE_USER (20<<3) >> 5, then
    # (PREFIX_BYTE_USER & 31) << 3; the public key prefix: PREFIX_BYTE_USER.
    return nkey_encode(b"\x95\x00", seed), nkey_encode(b"\xa0", ed25519_public(seed))


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


class PasswordHook:
    """A hook that logs in with a password and sets a new one (Postgres, Redis)."""

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


class PostgresHook(PasswordHook):
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


class RedisHook(PasswordHook):
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


# --- Kubernetes -------------------------------------------------------------------------


class Kube:
    """The Secrets of the Kubernetes API, with the projected API token."""

    def __init__(self, env, timeout):
        api = env.get("KUBE_API", "https://kubernetes.default.svc")
        if not api.startswith("https://"):
            raise RunError("KUBE_API must be an https:// URL")
        self.http = ApiHttp(api, env.get("KUBE_CACERT") or None, timeout)
        self.token_file = env.get("KUBE_TOKEN_FILE", "")

    def call(self, method, ref, body=None):
        token = read_file(self.token_file, "KUBE_TOKEN_FILE")
        path = "/api/v1/namespaces/%s/secrets/%s" % (urllib.parse.quote(ref["namespace"], safe=""),
                                                     urllib.parse.quote(ref["name"], safe=""))
        return self.http.call(method, path, body, {"Authorization": "Bearer " + token},
                              content_type="application/merge-patch+json")

    def get_secret(self, ref):
        """The Secret object, or None when it does not exist."""
        status, doc = self.call("GET", ref)
        if status == 200:
            return doc
        if status == 404:
            return None
        raise RunError("get Secret %s/%s: %s %s" % (ref["namespace"], ref["name"], status, errors_of(doc)))

    def secret_value(self, ref):
        status, doc = self.call("GET", ref)
        raw = ((doc.get("data") or {}).get(ref["key"]) if status == 200 and isinstance(doc, dict) else None)
        if not raw:
            raise HookError("read Secret %s/%s key %s: %s %s" % (ref["namespace"], ref["name"], ref["key"], status,
                                                                errors_of(doc)))
        try:
            return base64.b64decode(raw, validate=True).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            raise HookError("Secret %s/%s key %s is not UTF-8 text" % (ref["namespace"], ref["name"],
                                                                     ref["key"])) from None


# --- the Job ----------------------------------------------------------------------------


class Job:
    def __init__(self, op, env):
        if op not in OPS:
            raise RunError("unknown op '%s' (%s)" % (op, "|".join(OPS)))
        self.op, self.env = op, env
        self.timeout = timeout_seconds(env.get("BAO_CLIENT_TIMEOUT"))
        addr = env.get("BAO_ADDR", "")
        if not re.match(r"https://.", addr):
            raise RunError("BAO_ADDR must be an https:// URL")
        self.auth_mount = env.get("OB_AUTH_MOUNT") or "kubernetes"
        self.role = env.get("OB_ROLE", "")
        if not is_segment(self.auth_mount):
            raise RunError("OB_AUTH_MOUNT must be one path segment of [A-Za-z0-9._-]")
        if not is_segment(self.role):
            raise RunError("OB_ROLE must be a role name of [A-Za-z0-9._-]")
        cafile = env.get("BAO_CACERT") or None
        if cafile and not os.access(cafile, os.R_OK):
            raise RunError("BAO_CACERT (%s) is not readable" % cafile)
        self.bao = ApiHttp(addr, cafile, self.timeout)
        self.plan = {} if op == "probe" else json.loads(read_file(env.get("OB_PLAN_FILE", ""), "OB_PLAN_FILE"))
        self.mount = self.plan.get("mount", "")
        if op != "probe" and not is_segment(self.mount):
            raise RunError("the plan mount must be one path segment of [A-Za-z0-9._-]")
        self.token = None

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
        jwt = read_file(self.env.get("OB_JWT_FILE", ""), "OB_JWT_FILE")
        status, doc = self.bao.call("POST", "/v1/auth/%s/login" % self.auth_mount, {"role": self.role, "jwt": jwt})
        jwt = None
        token = ((doc.get("auth") or {}).get("client_token") or "") if status == 200 else ""
        if not token:
            result({"kind": "probe", "state": "login_failed", "error": "login to auth/%s as role %s failed: %s" % (
                self.auth_mount, self.role, errors_of(doc) or status)})
            raise RunError("login failed")
        self.token = sensitive(token)
        result({"kind": "probe", "state": "ok", "error": ""})

    def kv(self, method, kind, path, body=None, query=""):
        return self.bao.call(method, "/v1/%s/%s/%s%s" % (self.mount, kind, urllib.parse.quote(path), query), body,
                             {"X-Vault-Token": self.token})

    def revoke(self):
        if self.token:
            status, _ = self.bao.call("POST", "/v1/auth/token/revoke-self", {}, {"X-Vault-Token": self.token})
            if status not in (200, 204):
                log("token revoke failed (%s)" % status)
            self.token = None

    def where(self, path):
        return "%s/%s" % (self.mount, path)

    # --- ensure, status, delete ---

    def check_plan(self):
        """Validates every plan entry before anything is written."""
        entries = self.plan.get("entries")
        if not isinstance(entries, list):
            raise RunError("the plan has no entries")
        for n, e in enumerate(entries, 1):
            action, cid, path, keys = e.get("action"), e.get("id"), e.get("path"), e.get("keys") or {}
            if self.op == "delete" and action != "delete":
                raise RunError("plan entry %d: op delete has only delete entries, not '%s'" % (n, action))
            if self.op != "delete" and action not in ("write", "check"):
                raise RunError("plan entry %d: unknown action '%s'" % (n, action))
            if self.op == "status" and action == "write":
                raise RunError("plan entry %d: status never writes" % n)
            if not (isinstance(cid, str) and CRED_ID.fullmatch(cid)):
                raise RunError("plan entry %d: bad credential id '%s'" % (n, cid))
            if not is_kv_path(path):
                raise RunError("plan entry %d: bad KV path '%s'" % (n, path))
            if action == "write" and not keys:
                raise RunError("plan entry %d: write without keys" % n)
            for k, spec in keys.items():
                self.check_spec("plan entry %d (%s)" % (n, cid), k, spec)
        purge = self.plan.get("purge")
        if purge and (self.op != "delete" or not is_kv_path(purge) or purge.count("/") != 1):
            # Exactly <cluster_id>/<layer>: never the cluster or the mount root.
            raise RunError("bad purge prefix '%s' (op delete only, <cluster_id>/<layer>)" % purge)

    @staticmethod
    def check_spec(where, key, spec):
        t = spec.get("type") if isinstance(spec, dict) else None
        if not KV_KEY.fullmatch(key):
            raise RunError("%s: bad KV key '%s'" % (where, key))
        if t == "password":
            if not (isinstance(spec.get("length"), int) and 8 <= spec["length"] <= 256):
                raise RunError("%s: password length must be 8..256" % where)
        elif t == "hex":
            if not (isinstance(spec.get("bytes"), int) and 8 <= spec["bytes"] <= 128):
                raise RunError("%s: hex bytes must be 8..128" % where)
        elif t == "nkey_user":
            w = spec.get("writes")
            if not (isinstance(w, list) and len(w) == 2 and w[0] != w[1]
                    and all(isinstance(x, str) and KV_KEY.fullmatch(x) for x in w)):
                raise RunError("%s: bad nkey_user keys" % where)
        elif t != "static":
            raise RunError("%s: unknown generator '%s'" % (where, t))

    def meta(self, path):
        """(state exists | missing | deleted | error, current version, error) from the metadata."""
        status, doc = self.kv("GET", "metadata", path)
        if status == 404:
            return "missing", 0, ""
        data = doc.get("data") if status == 200 and isinstance(doc, dict) else None
        if not isinstance(data, dict):
            return "error", 0, "read %s: %s" % (self.where("metadata/" + path), errors_of(doc) or status)
        version = data.get("current_version")
        if not isinstance(version, int):
            return "error", 0, "cannot parse the metadata of %s" % path
        if version == 0:
            return "missing", 0, ""
        cur = (data.get("versions") or {}).get(str(version))
        if not isinstance(cur, dict):
            return "error", version, "cannot parse version %d of %s" % (version, path)
        deletion = cur.get("deletion_time") or ""
        # A future deletion_time is a scheduled deletion (delete_version_after):
        # the version is still live.
        now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
        if cur.get("destroyed") or (deletion and deletion[:19] <= now):
            return "deleted", version, ""
        return "exists", version, ""

    def exists_result(self, cid, action, path, version, keys):
        """The result of an existing entry: exists, or incomplete when it lacks keys."""
        names = [n for k, s in keys.items() for n in (s["writes"] if s.get("type") == "nkey_user" else [k])]
        if names:
            status, doc = self.kv("GET", "data", path, query="?version=%d" % version)
            data = (doc.get("data") or {}).get("data") if status == 200 and isinstance(doc, dict) else None
            if not isinstance(data, dict):
                return self.cred(cid, action, "error", version, "read %s: %s" % (
                    self.where(path), errors_of(doc) or status))
            missing = [n for n in names if n not in data]
            data = doc = None
            if missing:
                return self.cred(cid, action, "incomplete", version, (
                    "%s lacks key(s) %s (added to the registry after the entry was created); add them with bao kv "
                    "patch -mount=%s %s <key>=- (value on stdin without a trailing newline: printf %%s \"$V\" | "
                    "bao kv patch ...; a new version; docs/deploy/openbao.md \"Log in to OpenBao\")"
                    % (self.where(path), " ".join(missing), self.mount, path)))
        return self.cred(cid, action, "exists", version, "")

    def cred(self, cid, action, res, version, error):
        result({"kind": "credential", "id": cid, "action": action, "result": res, "version": version,
                "error": scrub(error)})
        if action == "check":
            return res not in ("error", "incomplete")
        return res in (("removed", "missing") if action == "delete" else ("created", "exists"))

    def write_cred(self, cid, path, keys):
        state, version, err = self.meta(path)
        if state == "exists":
            return self.exists_result(cid, "write", path, version, keys)
        if state == "deleted":
            return self.cred(cid, "write", "deleted", version, "the current version of %s is deleted or destroyed; "
                             "restore it (bao kv undelete) or remove its metadata" % self.where(path))
        if state == "error":
            return self.cred(cid, "write", "error", 0, err)
        data = {}
        for k, spec in keys.items():
            t = spec["type"]
            if t == "static":
                return self.cred(cid, "write", "missing", 0, "operator-supplied: write %s first (bao kv put -mount=%s "
                                 "%s ...)" % (self.where(path), self.mount, path))
            try:
                if t == "nkey_user":
                    data.update(zip(spec["writes"], sensitive(*nkey_user())))
                else:
                    data[k] = sensitive(generate(spec))
            except (RunError, ValueError):
                return self.cred(cid, "write", "error", 0, "%s generation failed" % t)
        status, doc = self.kv("POST", "data", path, {"options": {"cas": 0}, "data": data})
        data = None
        if status in (200, 204):
            return self.cred(cid, "write", "created", ((doc.get("data") or {}).get("version")) or 0, "")
        err = errors_of(doc)
        if status == 400 and "check-and-set" in err:
            # Created by someone else between the metadata read and the write.
            state, version, _ = self.meta(path)
            if state == "exists":
                return self.exists_result(cid, "write", path, version, keys)
            return self.cred(cid, "write", "error", version, "CAS mismatch on %s, then state %s" % (
                self.where(path), state))
        return self.cred(cid, "write", "error", 0, "write %s: %s" % (self.where(path), err or status))

    def check_cred(self, cid, path, keys):
        state, version, err = self.meta(path)
        if state == "exists":
            return self.exists_result(cid, "check", path, version, keys)
        return self.cred(cid, "check", state, version if state != "error" else 0, err)

    def present(self, path):
        """(present | absent | error, error) of the entry's metadata (present also
        without a live version)."""
        status, doc = self.kv("GET", "metadata", path)
        if status == 200:
            return "present", ""
        return ("absent", "") if status == 404 else ("error", errors_of(doc) or str(status))

    def delete_cred(self, cid, path):
        where = self.where("metadata/" + path)
        state, err = self.present(path)
        if state == "error":
            return self.cred(cid, "delete", "error", 0, "read %s: %s" % (where, err))
        if state == "absent":
            return self.cred(cid, "delete", "missing", 0, "")
        status, doc = self.kv("DELETE", "metadata", path)
        if status not in (200, 204):
            return self.cred(cid, "delete", "error", 0, "delete %s: %s" % (where, errors_of(doc) or status))
        state, err = self.present(path)
        if state != "absent":
            return self.cred(cid, "delete", "error", 0, "%s is still there after the delete%s" % (
                where, " (%s)" % err if err else ""))
        return self.cred(cid, "delete", "removed", 0, "")

    def list_keys(self, prefix):
        """The names under prefix (folders end in /); raises RunError on a read error."""
        status, doc = self.kv("GET", "metadata", prefix, query="?list=true")
        if status == 404:
            return []
        keys = (doc.get("data") or {}).get("keys") if status == 200 and isinstance(doc, dict) else None
        if not isinstance(keys, list):
            raise RunError("list %s: %s" % (self.where("metadata/" + prefix), errors_of(doc) or status))
        return [str(k) for k in keys]

    def purge(self, prefix):
        """Every entry left under <cluster_id>/<layer>/ (registry or not)."""
        removed, queue, visited = 0, [prefix], 0
        try:
            while queue:
                folder = queue.pop(0)
                visited += 1
                if visited > PURGE_MAX:
                    raise RunError("more than %d folders under %s" % (PURGE_MAX, prefix))
                for name in self.list_keys(folder):
                    base = name.removesuffix("/")
                    if not is_segment(base):
                        raise RunError("%s holds an entry whose name is not of [A-Za-z0-9._-] (%s); delete it by "
                                       "hand with bao kv metadata delete" % (
                                           self.where("metadata/" + folder), name[:64]))
                    if name != base:
                        queue.append(folder + "/" + base)
                        continue
                    status, doc = self.kv("DELETE", "metadata", folder + "/" + base)
                    if status not in (200, 204):
                        raise RunError("delete %s: %s" % (self.where("metadata/%s/%s" % (folder, base)),
                                                          errors_of(doc) or status))
                    removed += 1
            left = self.list_keys(prefix)
            if left:
                raise RunError("%s still lists %s after the purge (written meanwhile?)" % (
                    self.where("metadata/" + prefix), " ".join(left)[:200]))
        except RunError as err:
            result({"kind": "purge", "prefix": prefix, "state": "error", "removed": removed, "error": scrub(err)})
            return False
        result({"kind": "purge", "prefix": prefix, "state": "ok", "removed": removed, "error": ""})
        return True

    def run_plan(self):
        ok = True
        for e in self.plan["entries"]:
            keys = e.get("keys") or {}
            if e["action"] == "write":
                ok = self.write_cred(e["id"], e["path"], keys) and ok
            elif e["action"] == "delete":
                ok = self.delete_cred(e["id"], e["path"]) and ok
            else:
                ok = self.check_cred(e["id"], e["path"], keys) and ok
        # After the deletes; skipped when one failed (the entry would count as a
        # leftover and hide the failure).
        if ok and self.plan.get("purge"):
            ok = self.purge(self.plan["purge"])
        if not ok:
            raise RunError("one or more credentials failed (see the credential results)")

    # --- import ---

    def import_result(self, entry, res, version, error):
        result({"kind": "credential", "id": entry["id"], "action": "import", "result": res, "version": version,
                "error": scrub(error)})

    def read_legacy(self, kube):
        """{(ns, name): Secret or None} for every legacy ref, and the found count."""
        cache = {}
        for entry in self.plan["entries"]:
            for refs in entry["keys"].values():
                for ref in refs:
                    k = (ref["namespace"], ref["name"])
                    if k not in cache:
                        cache[k] = kube.get_secret(ref)
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
                            sensitive(base64.b64decode(raw, validate=True).decode("utf-8"))
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
                self.import_result(entry, "error", 0, err)
                bad += 1
            elif not data:
                required = entry.get("required") and found > 0
                where = ", ".join(sorted({"%s/%s.%s" % (r["namespace"], r["name"], r["key"])
                                          for refs in entry["keys"].values() for r in refs})) or "no legacy Secret"
                self.import_result(entry, "missing" if required else "absent", 0, (
                    "required, but no legacy value in %s (the running deployment's users or clients would keep a "
                    "value the store does not hold; if the feature that uses it is enabled for the first time in "
                    "this run, migrate with it disabled and enable it afterwards)" % where) if required else "")
                bad += 1 if required else 0
            else:
                to_write.append((entry, data))
            data = None
        return to_write, bad

    def compare(self, entry, data):
        """(result, version, error) of the entry's current value: None = no entry."""
        status, doc = self.kv("GET", "data", entry["path"])
        if status == 404 and not ((doc.get("data") or {}).get("metadata") or {}).get("version"):
            return None
        current = (doc.get("data") or {}).get("data") if status == 200 else None
        version = (((doc.get("data") or {}).get("metadata") or {}).get("version")) or 0
        where = self.where(entry["path"])
        if current is None:
            if status == 404:
                return "error", version, ("the current version of %s is deleted; restore it (bao kv undelete) "
                                          "or remove its metadata, then re-run" % where)
            return "error", version, "read %s: %s" % (where, errors_of(doc) or status)
        same = all(current.get(k) == v for k, v in data.items())
        current = None
        if same:
            return "exists", version, ""
        return "conflict", version, ("%s already holds other values than the running deployment; it is not "
                                     "overwritten. Remove it (bao kv metadata delete) if it was written by "
                                     "mistake, then re-run" % where)

    def import_write(self, entry, data):
        status, doc = self.kv("POST", "data", entry["path"], {"options": {"cas": 0}, "data": data})
        if status in (200, 204):
            return "created", ((doc.get("data") or {}).get("version")) or 0, ""
        err = errors_of(doc)
        if status == 400 and "check-and-set" in err:
            # Created between the compare and the write.
            return self.compare(entry, data) or ("error", 0, "CAS mismatch on %s, then no entry"
                                                 % self.where(entry["path"]))
        return "error", 0, "write %s: %s" % (self.where(entry["path"]), err or status)

    def patch(self, kube, ref, action, body):
        status, doc = kube.call("PATCH", ref, body)
        if status == 200:
            return "patched", ""
        if status == 404:
            return "missing", ""
        return "error", "patch %s: %s %s" % (action, status, errors_of(doc))

    def handover(self, kube):
        bad = 0
        for ref in self.plan.get("handover", []):
            try:
                secret = kube.get_secret(ref)
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
                    res, msg = self.patch(kube, ref, "keep", {"metadata": {"annotations": {KEEP: "keep"}}})
            secret = None
            bad += res == "error"
            result({"kind": "secret", "namespace": ref["namespace"], "name": ref["name"], "action": "keep",
                    "result": res, "error": msg})
        label, annotation = self.plan["markup_label"], self.plan["markup_annotation"]
        for ref in self.plan.get("unmark", []):
            res, msg = self.patch(kube, ref, "unmark", {"metadata": {"labels": {label: None},
                                                                     "annotations": {annotation: None}}})
            bad += res == "error"
            result({"kind": "secret", "namespace": ref["namespace"], "name": ref["name"], "action": "unmark",
                    "result": res, "error": msg})
        return bad

    def run_import(self):
        kube = Kube(self.env, self.timeout)
        cache, found = self.read_legacy(kube)
        to_write, bad = self.evaluate(cache, found)
        cache = None
        pending = []
        while to_write:
            entry, data = to_write.pop(0)
            current = self.compare(entry, data)
            if current is None:
                pending.append((entry, data))
            else:
                bad += current[0] != "exists"
                self.import_result(entry, *current)
            data = None
        to_write = pending
        if bad:
            for entry, _ in to_write:
                self.import_result(entry, "error", 0, "not written: another credential failed its check")
            raise RunError("one or more credentials failed their check; nothing was written")
        failed = 0
        while to_write:
            entry, data = to_write.pop(0)
            res, version, err = self.import_write(entry, data)
            data = None
            failed += res not in ("created", "exists")
            self.import_result(entry, res, version, err)
        if failed:
            raise RunError("one or more credentials could not be imported; no Secret was changed")
        if self.handover(kube):
            raise RunError("one or more Secrets could not be patched")

    # --- rotate ---

    def report(self, res, version, previous, server, error=""):
        result({"kind": "credential", "id": self.plan["id"], "action": "rotate", "hook": self.plan["hook"],
                "result": res, "version": version, "previous_version": previous, "server": server,
                "error": scrub(error)})

    def read_current(self):
        """(version, data) of the live current version, or reports and returns None."""
        status, doc = self.kv("GET", "data", self.plan["path"])
        meta = ((doc.get("data") or {}).get("metadata") or {}) if isinstance(doc, dict) else {}
        version = meta.get("version") or 0
        data = (doc.get("data") or {}).get("data") if status == 200 else None
        where = self.where(self.plan["path"])
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

    def rotate_write(self, data, cas):
        status, doc = self.kv("POST", "data", self.plan["path"], {"options": {"cas": cas}, "data": data})
        if status in (200, 204):
            return ((doc.get("data") or {}).get("version")) or 0, ""
        return 0, "write %s (cas=%d): %s" % (self.where(self.plan["path"]), cas, errors_of(doc) or status)

    def hook(self):
        target = self.plan.get("target") or {}
        name = self.plan["hook"]
        timeout = int(self.plan.get("timeout") or 15)
        if name == "postgres-alter-user":
            return PostgresHook(target, timeout)
        if name == "redis-acl-set":
            return RedisHook(target, timeout)
        return KeycloakHook(target, timeout, self.plan.get("keycloak") or {}, Kube(self.env, self.timeout))

    def run_rotate(self):
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
            err = err if isinstance(err, (HookError, RunError)) else "unexpected %s" % type(err).__name__
            self.report("precheck_failed", version, version, "unchanged",
                        "%s precheck with the current value failed, nothing changed: %s" % (self.plan["hook"], err))
            raise RunError("precheck failed") from None
        new = sensitive(generate(spec))
        new_data = dict(old_data)
        new_data[key] = new
        written, err = self.rotate_write(new_data, version)
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
            hook_err = caught if isinstance(caught, (HookError, RunError)) else "unexpected %s" % type(caught).__name__
            try:
                restored_server = hook.undo(old, new)
            except Exception:  # noqa: BLE001
                restored_server = False
            server = "restored" if restored_server else "unknown"
            back, werr = self.rotate_write(old_data, written)
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

    def run(self):
        if self.op in ("ensure", "status", "delete"):
            self.check_plan()
        elif self.op == "rotate":
            for k in ("id", "path", "hook", "keys"):
                if not self.plan.get(k):
                    raise RunError("the plan has no %s" % k)
            if self.plan["hook"] not in HOOKS:
                raise RunError("unknown hook %s" % self.plan["hook"])
        self.probe()
        if self.op == "import":
            self.run_import()
        elif self.op == "rotate":
            self.run_rotate()
        elif self.op != "probe":
            self.run_plan()


def interrupted(signum, frame):
    raise RunError("interrupted by signal")


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    # A killed Job (deadline, eviction) still undoes, revokes and prints "done".
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, interrupted)
    job = None
    try:
        job = Job(argv[0] if len(argv) == 1 else "", os.environ)
        job.run()
    except RunError as err:
        log(scrub(err))
        if job:
            job.revoke()
        result({"kind": "done", "state": "failed", "error": scrub(err)})
        return 1
    except Exception as err:  # noqa: BLE001 (report any crash without a traceback, which could hold data)
        log("unexpected %s" % type(err).__name__)
        if job:
            job.revoke()
        result({"kind": "done", "state": "failed", "error": "unexpected %s" % type(err).__name__})
        return 1
    job.revoke()
    result({"kind": "done", "state": "ok", "error": ""})
    return 0


if __name__ == "__main__":
    sys.exit(main())
