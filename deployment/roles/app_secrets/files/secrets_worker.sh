#!/bin/sh
# Copyright (C) 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0
#
# app_secrets openbao adapter: the in-cluster worker.
#
# Runs as the only container of the erag-secrets worker Job (OpenBao image:
# POSIX sh, busybox and the bao CLI), and in tests/test_openbao_adapter.yaml.
#
#   /bin/sh secrets_worker.sh <probe|ensure|status|delete>
#
#   probe   OpenBao reachable, initialized and unsealed (sys/health through
#           bao status), then a Kubernetes-auth login as OB_ROLE.
#   ensure  probe, then for every plan line:
#             write  create the KV v2 entry with cas=0 when it does not exist
#                    (CAS mismatch = created meanwhile = exists, skip); an
#                    existing entry must have every key of the line
#             check  existence and current version; with keys, an existing
#                    entry must also have every key of the line
#   status  probe, then "check" for every plan line (status plans carry no
#           keys: metadata only).
#   delete  probe, then for every plan line:
#             delete  remove the metadata and every version of the entry
#                     (bao kv metadata delete), then read it back: it must be
#                     gone
#             purge   (teardown of a whole layer, last line) remove every
#                     entry left under <cluster_id>/<layer>/ (entries the
#                     registry does not know, e.g. other erag/user/* names),
#                     then list the prefix again: it must be empty
#
# Inputs, all non-secret:
#   argv           the op name only
#   BAO_ADDR       OpenBao API address
#   BAO_CACERT     CA bundle (ca.crt only) for BAO_ADDR
#   OB_AUTH_MOUNT  Kubernetes auth mount (auth/<mount>/login)
#   OB_ROLE        Kubernetes auth role (erag-secrets-worker)
#   OB_JWT_FILE    projected ServiceAccount token (audience of OB_ROLE)
#   OB_KV_MOUNT    KV v2 mount
#   OB_PLAN_FILE   plan, one credential per line:
#                    <write|check> <credential-id> <path> [<kv_key>=<spec> ...]
#                    delete <credential-id> <path>          (op delete)
#                    purge <cluster_id>/<layer>             (op delete)
#                  (nkey_user:<s>:<p> stands for the two keys s and p)
#                  path is relative to the mount (<cluster_id>/<layer>/...);
#                  spec is one of
#                    password:<length>:<special 0|1>
#                    hex:<bytes>
#                    nkey_user:<seed_key>:<public_key_key>
#                    static            (operator-supplied: never generated)
#   OB_WORK_DIR    writable in-memory directory (HOME of every bao call)
#
# Secrets: generated values and the OpenBao token live only in shell variables
# of this process. They are never printed, written to a file, exported or put
# in argv: values reach OpenBao as JSON on stdin, and the token is set as
# BAO_TOKEN in the environment of each single bao call that needs it. NKey
# pairs come from an ephemeral in-memory dev-mode OpenBao on 127.0.0.1 inside
# this pod (transit ed25519 key export); its random root token is likewise
# passed in its environment only, and it stores no token file.
#
# Output (stdout): one line per result, "ERAG_SECRETS_RESULT <json>":
#   {"kind":"probe","state":"ok|unreachable|uninitialized|sealed|login_failed","error":"..."}
#   {"kind":"credential","id":"...","action":"write|check|delete","result":"created|exists|missing|deleted|incomplete|removed|error","version":N,"error":"..."}
#   delete: removed (there was an entry, now gone) or missing (none was there).
#   {"kind":"purge","prefix":"...","state":"ok|error","removed":N,"error":"..."}
#   purge: N entries outside the plan removed; ok = the prefix lists nothing.
#   incomplete: the entry exists but lacks keys of the line (e.g. a key added
#   to the registry later); error names the keys. Only the presence of each
#   key is read (bao kv get -field, output discarded), never printed.
#   {"kind":"done","state":"ok|failed","error":"..."}   (always last, from the EXIT trap)
# Exit: 0 when every credential is created/exists (status: any result but
# error; delete: removed/missing and purge ok), 1 otherwise. Diagnostics go
# to stderr and never contain a value.

set -u
set -f
umask 077

OP=${1:-}
OB_AUTH_MOUNT=${OB_AUTH_MOUNT:-kubernetes}
OB_ROLE=${OB_ROLE:-}
OB_JWT_FILE=${OB_JWT_FILE:-}
OB_KV_MOUNT=${OB_KV_MOUNT:-}
OB_PLAN_FILE=${OB_PLAN_FILE:-}
OB_WORK_DIR=${OB_WORK_DIR:-}
BAO_CLIENT_TIMEOUT=${BAO_CLIENT_TIMEOUT:-15s}
export BAO_CLIENT_TIMEOUT
# Never pick up a token from the environment or a token helper file.
unset BAO_TOKEN VAULT_TOKEN

PREFIX="ERAG_SECRETS_RESULT"
TOKEN=
DEV_PID=
DEV_ADDR=
DEV_TOKEN=
FAILED=false
DONE_ERR=
NKEY_N=0

log() { printf 'erag-secrets-worker: %s\n' "$*" >&2; }

# JSON string escape: whitespace folded to spaces, other control characters
# dropped, then backslash and quote escaped.
jstr() {
	printf '%s' "$1" | tr '\n\r\t' '   ' | tr -d '\000-\037\177' | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'
}

# Last lines of a bao error (bao errors never echo the request body or token).
errtext() { printf '%s' "$1" | grep -v '^ *$' | tail -n 3; }

result() { printf '%s %s\n' "$PREFIX" "$1"; }

# shellcheck disable=SC2329 # invoked by the EXIT trap
cleanup() {
	if [ -n "$TOKEN" ]; then
		BAO_TOKEN="$TOKEN" bao token revoke -self >/dev/null 2>&1 || log "token revoke failed"
		TOKEN=
	fi
	dev_stop
	if [ "$FAILED" = true ]; then
		result "{\"kind\":\"done\",\"state\":\"failed\",\"error\":\"$(jstr "$DONE_ERR")\"}"
		exit 1
	fi
	result '{"kind":"done","state":"ok","error":""}'
	exit 0
}
trap cleanup EXIT
trap 'DONE_ERR="interrupted by signal"; FAILED=true; exit 1' HUP INT TERM

die() {
	DONE_ERR=$*
	FAILED=true
	log "$*"
	exit 1
}

probe_result() {
	result "{\"kind\":\"probe\",\"state\":\"$1\",\"error\":\"$(jstr "$2")\"}"
}

# cred_result <id> <action> <result> <version> <error>
cred_result() {
	result "{\"kind\":\"credential\",\"id\":\"$1\",\"action\":\"$2\",\"result\":\"$3\",\"version\":$4,\"error\":\"$(jstr "$5")\"}"
}

is_uint() { case "$1" in '' | *[!0-9]*) return 1 ;; *) return 0 ;; esac; }

# One path segment of [A-Za-z0-9._-], not . or ..
is_segment() { case "$1" in '' | . | .. | *[!A-Za-z0-9._-]*) return 1 ;; esac; }

# Relative KV path: segments of [A-Za-z0-9._-], no empty, . or .. segment.
is_kv_path() {
	case "$1" in '' | /* | */ | *//* | *[!A-Za-z0-9._/-]*) return 1 ;; esac
	old_ifs=$IFS
	IFS=/
	for seg in $1; do
		is_segment "$seg" || { IFS=$old_ifs; return 1; }
	done
	IFS=$old_ifs
}

is_cred_id() {
	case "$1" in */*/* | /* | */ | *[!a-z0-9/-]*) return 1 ;; */*) return 0 ;; *) return 1 ;; esac
}

is_kv_key() { case "$1" in '' | *[!a-z0-9_]* | [!a-z]*) return 1 ;; *) return 0 ;; esac; }

# ── Parameters ───────────────────────────────────────────────────────────────

check_params() {
	case "$OP" in probe | ensure | status | delete) ;; *) die "unknown op '$OP' (probe|ensure|status|delete)" ;; esac
	[ -n "${BAO_ADDR:-}" ] || die "BAO_ADDR is not set"
	case "$BAO_ADDR" in https://?* | http://?*) ;; *) die "BAO_ADDR must be an http(s):// URL" ;; esac
	is_segment "$OB_AUTH_MOUNT" || die "OB_AUTH_MOUNT must be one path segment of [A-Za-z0-9._-]"
	is_segment "$OB_ROLE" || die "OB_ROLE must be a role name of [A-Za-z0-9._-]"
	[ -r "$OB_JWT_FILE" ] || die "OB_JWT_FILE ($OB_JWT_FILE) is not readable"
	[ -d "$OB_WORK_DIR" ] && [ -w "$OB_WORK_DIR" ] || die "OB_WORK_DIR ($OB_WORK_DIR) is not a writable directory"
	if [ -n "${BAO_CACERT:-}" ] && [ ! -r "$BAO_CACERT" ]; then
		die "BAO_CACERT ($BAO_CACERT) is not readable"
	fi
	if [ "$OP" != probe ]; then
		is_segment "$OB_KV_MOUNT" || die "OB_KV_MOUNT must be one path segment of [A-Za-z0-9._-]"
		[ -r "$OB_PLAN_FILE" ] || die "OB_PLAN_FILE ($OB_PLAN_FILE) is not readable"
	fi
	HOME=$OB_WORK_DIR/home
	TMPDIR=$OB_WORK_DIR/tmp
	mkdir -p "$HOME" "$TMPDIR" || die "cannot create $HOME and $TMPDIR"
	export HOME TMPDIR
}

# Validates every plan line before anything is written.
check_plan() {
	n=0
	while IFS= read -r line || [ -n "$line" ]; do
		case "$line" in '' | '#'*) continue ;; esac
		n=$((n + 1))
		# shellcheck disable=SC2086
		set -- $line
		if [ "$OP" = delete ]; then
			case "$1" in
			delete)
				[ $# -eq 3 ] || die "plan line $n: expected delete <id> <path>"
				is_cred_id "$2" || die "plan line $n: bad credential id '$2'"
				is_kv_path "$3" || die "plan line $n: bad KV path '$3'"
				;;
			purge)
				[ $# -eq 2 ] || die "plan line $n: expected purge <cluster_id>/<layer>"
				# Exactly <cluster_id>/<layer>: never the cluster or the mount root.
				case "$2" in */*/*) die "plan line $n: purge prefix must be <cluster_id>/<layer>" ;; esac
				{ is_kv_path "$2" && case "$2" in */*) true ;; *) false ;; esac; } ||
					die "plan line $n: bad purge prefix '$2'"
				;;
			*) die "plan line $n: op delete has only delete and purge lines, not '$1'" ;;
			esac
			continue
		fi
		[ $# -ge 3 ] || die "plan line $n: expected <action> <id> <path> [<key>=<spec> ...]"
		case "$1" in write | check) ;; *) die "plan line $n: unknown action '$1'" ;; esac
		[ "$OP" = status ] && [ "$1" = write ] && die "plan line $n: status never writes"
		is_cred_id "$2" || die "plan line $n: bad credential id '$2'"
		is_kv_path "$3" || die "plan line $n: bad KV path '$3'"
		[ "$1" = write ] && [ $# -lt 4 ] && die "plan line $n: write without keys"
		id=$2
		shift 3
		for ks in "$@"; do
			k=${ks%%=*}
			spec=${ks#*=}
			[ "$k" != "$ks" ] || die "plan line $n ($id): bad key spec '$ks'"
			is_kv_key "$k" || die "plan line $n ($id): bad KV key '$k'"
			case "$spec" in
			password:*:*)
				len=${spec#password:}
				len=${len%%:*}
				sp=${spec##*:}
				{ is_uint "$len" && [ "$len" -ge 8 ] && [ "$len" -le 256 ]; } || die "plan line $n ($id): password length must be 8..256"
				case "$sp" in 0 | 1) ;; *) die "plan line $n ($id): password special must be 0 or 1" ;; esac
				;;
			hex:*)
				b=${spec#hex:}
				{ is_uint "$b" && [ "$b" -ge 8 ] && [ "$b" -le 128 ]; } || die "plan line $n ($id): hex bytes must be 8..128"
				;;
			nkey_user:*:*)
				s=${spec#nkey_user:}
				p=${s#*:}
				s=${s%%:*}
				{ is_kv_key "$s" && is_kv_key "$p" && [ "$s" != "$p" ]; } || die "plan line $n ($id): bad nkey_user keys"
				;;
			static) ;;
			*) die "plan line $n ($id): unknown generator '$spec'" ;;
			esac
		done
	done <"$OB_PLAN_FILE"
}

# ── OpenBao access ───────────────────────────────────────────────────────────

probe() {
	out=$(bao status -format=json 2>&1)
	flat=$(printf '%s' "$out" | tr -d ' \n\r\t')
	case "$flat" in
	*'"initialized":false'*)
		probe_result uninitialized "OpenBao at $BAO_ADDR is not initialized"
		die "OpenBao is not initialized"
		;;
	*'"sealed":true'*)
		probe_result sealed "OpenBao at $BAO_ADDR is sealed"
		die "OpenBao is sealed"
		;;
	*'"sealed":false'*) ;;
	*)
		probe_result unreachable "cannot read the seal status of $BAO_ADDR: $(errtext "$out")"
		die "OpenBao is unreachable"
		;;
	esac
	# stdout only: a warning on stderr must not end up in the token.
	if ! TOKEN=$(bao write -field=token "auth/$OB_AUTH_MOUNT/login" role="$OB_ROLE" jwt=@"$OB_JWT_FILE" 2>"$OB_WORK_DIR/login.err"); then
		TOKEN=
		probe_result login_failed "login to auth/$OB_AUTH_MOUNT as role $OB_ROLE failed: $(errtext "$(cat "$OB_WORK_DIR/login.err")")"
		die "login failed"
	fi
	rm -f "$OB_WORK_DIR/login.err"
	case "$TOKEN" in '' | *[!A-Za-z0-9._-]*)
		TOKEN=
		probe_result login_failed "login to auth/$OB_AUTH_MOUNT as role $OB_ROLE returned no token"
		die "login returned no token"
		;;
	esac
	probe_result ok ""
}

# meta <path>: sets M_STATE (exists | missing | deleted | error), M_VERSION, M_ERR.
meta() {
	M_VERSION=0
	M_ERR=
	if out=$(BAO_TOKEN="$TOKEN" bao read -format=json "$OB_KV_MOUNT/metadata/$1" 2>&1); then
		flat=$(printf '%s' "$out" | tr -d ' \n\r\t')
		M_VERSION=$(printf '%s' "$flat" | sed -n 's/.*"current_version":\([0-9]*\).*/\1/p')
		is_uint "$M_VERSION" || { M_STATE=error; M_VERSION=0; M_ERR="cannot parse the metadata of $1"; return; }
		if [ "$M_VERSION" -eq 0 ]; then
			M_STATE=missing
			return
		fi
		# versions is a map keyed by version number; take the current one.
		cur=$(printf '%s' "$flat" | sed -n "s/.*\"versions\":{.*\"$M_VERSION\":{\([^}]*\)}.*/\1/p")
		case "$cur" in
		*'"destroyed":true'*) M_STATE=deleted ;;
		*'"deletion_time":""'*) M_STATE=exists ;;
		*'"deletion_time":"'*)
			# A future deletion_time is a scheduled deletion (delete_version_after):
			# the version is still live. RFC 3339 UTC times as YYYYMMDDhhmmss.
			dt=$(printf '%s' "$cur" | sed -n 's/.*"deletion_time":"\([^"]*\)".*/\1/p' | cut -c1-19 | tr -dc '0-9')
			now=$(date -u +%Y%m%d%H%M%S)
			if is_uint "$dt" && [ "$dt" -gt "$now" ]; then M_STATE=exists; else M_STATE=deleted; fi
			;;
		*) M_STATE=error; M_ERR="cannot parse version $M_VERSION of $1" ;;
		esac
	else
		case "$out" in
		*'No value found at'*) M_STATE=missing ;;
		*) M_STATE=error; M_ERR=$(errtext "$out") ;;
		esac
	fi
}

# ── Generators ───────────────────────────────────────────────────────────────

# gen_password <length> <special>: sets VAL. With special, the value holds at
# least one digit, upper-case, lower-case and special character (password
# policies such as the Keycloak realm's): drawn again until it does.
GP_SPECIAL='!#%+,.:=@^_~-'
gen_password() {
	# Four classes need four characters.
	if [ "$2" = 1 ] && [ "$1" -lt 4 ]; then VAL=; return 1; fi
	_gp_try=0
	while [ "$_gp_try" -lt 100 ]; do
		_gp_try=$((_gp_try + 1))
		if [ "$2" = 1 ]; then
			VAL=$(tr -dc "A-Za-z0-9$GP_SPECIAL" </dev/urandom | head -c "$1")
		else
			VAL=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c "$1")
		fi
		[ ${#VAL} -eq "$1" ] || { VAL=; return 1; }
		[ "$2" = 1 ] || return 0
		case "$VAL" in *[[:digit:]]*) ;; *) continue ;; esac
		case "$VAL" in *[[:upper:]]*) ;; *) continue ;; esac
		case "$VAL" in *[[:lower:]]*) ;; *) continue ;; esac
		# Quoted, so the set is literal ('!' does not negate it).
		case "$VAL" in *["$GP_SPECIAL"]*) return 0 ;; esac
	done
	VAL=
	return 1
}

# gen_hex <bytes>: sets VAL.
gen_hex() {
	VAL=$(od -An -vtx1 -N"$1" /dev/urandom | tr -d ' \n')
	[ ${#VAL} -eq $(($1 * 2)) ] || { VAL=; return 1; }
}

dev_stop() {
	if [ -n "$DEV_PID" ]; then
		kill "$DEV_PID" 2>/dev/null
		wait "$DEV_PID" 2>/dev/null
		DEV_PID=
	fi
	DEV_TOKEN=
}

# Ephemeral dev-mode OpenBao on 127.0.0.1 (in-memory, unsealed, a random root
# token given in its environment, no token file), with transit enabled.
dev_start() {
	[ -n "$DEV_PID" ] && return 0
	for _try in 1 2 3; do
		port=$(od -An -N2 -tu2 /dev/urandom | tr -d ' ')
		port=$((20000 + port % 30000))
		DEV_ADDR=http://127.0.0.1:$port
		gen_password 32 0 || return 1
		DEV_TOKEN=$VAL
		VAL=
		mkdir -p "$OB_WORK_DIR/dev" || return 1
		HOME=$OB_WORK_DIR/dev BAO_DEV_ROOT_TOKEN_ID="$DEV_TOKEN" \
			bao server -dev -dev-no-store-token -dev-listen-address="127.0.0.1:$port" >/dev/null 2>&1 &
		DEV_PID=$!
		i=0
		while [ "$i" -lt 50 ]; do
			if bao status -address="$DEV_ADDR" >/dev/null 2>&1; then
				if BAO_TOKEN="$DEV_TOKEN" bao secrets enable -address="$DEV_ADDR" transit >/dev/null 2>&1; then
					return 0
				fi
				break
			fi
			kill -0 "$DEV_PID" 2>/dev/null || break
			sleep 0.2
			i=$((i + 1))
		done
		dev_stop
	done
	return 1
}

# NKey encoding (nats-io/nkeys): prefix bytes + payload, CRC-16/XMODEM
# little-endian, base32 (RFC 4648, no padding). Hex in on stdin, text out.
nkey_encode() {
	awk '
	function hv(c) { return index("0123456789abcdef", c) - 1 }
	{
		n = length($0) / 2
		for (i = 0; i < n; i++) b[i] = hv(substr($0, 2 * i + 1, 1)) * 16 + hv(substr($0, 2 * i + 2, 1))
		crc = 0
		for (i = 0; i < n; i++) {
			crc = xor(crc, lshift(b[i], 8))
			for (j = 0; j < 8; j++) {
				if (and(crc, 32768)) crc = xor(lshift(crc, 1), 4129); else crc = lshift(crc, 1)
				crc = and(crc, 65535)
			}
		}
		b[n] = and(crc, 255); b[n + 1] = rshift(crc, 8); n += 2
		A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
		out = ""; buf = 0; bits = 0
		for (i = 0; i < n; i++) {
			buf = or(lshift(buf, 8), b[i]); bits += 8
			while (bits >= 5) {
				out = out substr(A, and(rshift(buf, bits - 5), 31) + 1, 1)
				bits -= 5; buf = and(buf, lshift(1, bits) - 1)
			}
		}
		if (bits > 0) out = out substr(A, and(lshift(buf, 5 - bits), 31) + 1, 1)
		printf "%s", out
	}'
}

# gen_nkey_user: sets SEED (SU...) and PUB (U...) from one ed25519 key.
gen_nkey_user() {
	SEED=
	PUB=
	dev_start || return 1
	NKEY_N=$((NKEY_N + 1))
	k=nkey$NKEY_N
	BAO_TOKEN="$DEV_TOKEN" bao write -address="$DEV_ADDR" -f "transit/keys/$k" type=ed25519 exportable=true >/dev/null 2>&1 || return 1
	# The export is the 64-byte ed25519 private key: 32-byte seed || 32-byte public key.
	raw=$(BAO_TOKEN="$DEV_TOKEN" bao read -address="$DEV_ADDR" -format=json "transit/export/signing-key/$k" 2>/dev/null |
		tr -d ' \n\r\t' | sed -n 's/.*"keys":{"1":"\([A-Za-z0-9+/=]*\)"}.*/\1/p' |
		base64 -d 2>/dev/null | od -An -vtx1 | tr -d ' \n')
	BAO_TOKEN="$DEV_TOKEN" bao write -address="$DEV_ADDR" "transit/keys/$k/config" deletion_allowed=true >/dev/null 2>&1
	BAO_TOKEN="$DEV_TOKEN" bao delete -address="$DEV_ADDR" "transit/keys/$k" >/dev/null 2>&1
	[ ${#raw} -eq 128 ] || { raw=; return 1; }
	# Seed prefix: PREFIX_BYTE_SEED (18<<3) | PREFIX_BYTE_USER (20<<3) >> 5, then
	# (PREFIX_BYTE_USER & 31) << 3; public key prefix: PREFIX_BYTE_USER.
	SEED=$(printf '9500%s' "$(printf '%s' "$raw" | cut -c1-64)" | nkey_encode)
	PUB=$(printf 'a0%s' "$(printf '%s' "$raw" | cut -c65-128)" | nkey_encode)
	raw=
	case "$SEED" in SU?*) ;; *) SEED=; PUB=; return 1 ;; esac
	case "$PUB" in U?*) ;; *) SEED=; PUB=; return 1 ;; esac
}

# ── Credentials ──────────────────────────────────────────────────────────────

# key_names <key=spec>...: sets KEYS, the KV keys the specs stand for.
key_names() {
	KEYS=
	for ks in "$@"; do
		k=${ks%%=*}
		spec=${ks#*=}
		case "$spec" in
		nkey_user:*)
			s=${spec#nkey_user:}
			KEYS="$KEYS ${s%%:*} ${s#*:}"
			;;
		*) KEYS="$KEYS $k" ;;
		esac
	done
}

# missing_keys <path> <key=spec>...: sets MISSING (space-separated key names
# version M_VERSION lacks) and K_ERR (a read error). The value of each key is
# read to /dev/null only.
missing_keys() {
	path=$1
	shift
	MISSING=
	K_ERR=
	key_names "$@"
	for k in $KEYS; do
		if ! BAO_TOKEN="$TOKEN" bao kv get -mount="$OB_KV_MOUNT" -version="$M_VERSION" -field="$k" "$path" >/dev/null 2>"$OB_WORK_DIR/field.err"; then
			case "$(cat "$OB_WORK_DIR/field.err")" in
			*'not present in'*) MISSING="$MISSING${MISSING:+ }$k" ;;
			*) K_ERR="read $OB_KV_MOUNT/$path: $(errtext "$(cat "$OB_WORK_DIR/field.err")")" ;;
			esac
		fi
	done
	rm -f "$OB_WORK_DIR/field.err"
}

# exists_result <id> <action> <path> <key=spec>...: the result of an existing
# entry (exists, or incomplete when it lacks keys). Returns 1 unless exists.
exists_result() {
	id=$1
	action=$2
	path=$3
	shift 3
	[ $# -gt 0 ] || { cred_result "$id" "$action" exists "$M_VERSION" ""; return 0; }
	missing_keys "$path" "$@"
	if [ -n "$K_ERR" ]; then
		cred_result "$id" "$action" error "$M_VERSION" "$K_ERR"
		return 1
	fi
	if [ -n "$MISSING" ]; then
		cred_result "$id" "$action" incomplete "$M_VERSION" "$OB_KV_MOUNT/$path lacks key(s) $MISSING (added to the registry after the entry was created); add them with bao kv patch -mount=$OB_KV_MOUNT $path <key>=- (value on stdin without a trailing newline: printf %s \"\$V\" | bao kv patch ...; a new version; docs/deploy/openbao.md \"Log in to OpenBao\")"
		return 1
	fi
	cred_result "$id" "$action" exists "$M_VERSION" ""
}

# write_cred <id> <path> <key=spec>...: create the entry with cas=0.
write_cred() {
	id=$1
	path=$2
	shift 2
	meta "$path"
	case "$M_STATE" in
	exists) exists_result "$id" write "$path" "$@"; return ;;
	deleted)
		cred_result "$id" write deleted "$M_VERSION" "the current version of $OB_KV_MOUNT/$path is deleted or destroyed; restore it (bao kv undelete) or remove its metadata"
		return 1
		;;
	error) cred_result "$id" write error 0 "$M_ERR"; return 1 ;;
	esac
	data=
	for ks in "$@"; do
		k=${ks%%=*}
		spec=${ks#*=}
		case "$spec" in
		static)
			data=
			cred_result "$id" write missing 0 "operator-supplied: write $OB_KV_MOUNT/$path first (bao kv put -mount=$OB_KV_MOUNT $path ...)"
			return 1
			;;
		password:*)
			len=${spec#password:}
			len=${len%%:*}
			gen_password "$len" "${spec##*:}" || { data=; cred_result "$id" write error 0 "password generation failed"; return 1; }
			data="$data${data:+,}\"$k\":\"$VAL\""
			;;
		hex:*)
			gen_hex "${spec#hex:}" || { data=; cred_result "$id" write error 0 "hex generation failed"; return 1; }
			data="$data${data:+,}\"$k\":\"$VAL\""
			;;
		nkey_user:*)
			s=${spec#nkey_user:}
			p=${s#*:}
			s=${s%%:*}
			gen_nkey_user || { data=; cred_result "$id" write error 0 "nkey_user generation failed"; return 1; }
			data="$data${data:+,}\"$s\":\"$SEED\",\"$p\":\"$PUB\""
			SEED=
			PUB=
			;;
		esac
		VAL=
	done
	if out=$(printf '{"options":{"cas":0},"data":{%s}}' "$data" |
		BAO_TOKEN="$TOKEN" bao write -format=json "$OB_KV_MOUNT/data/$path" - 2>&1); then
		data=
		v=$(printf '%s' "$out" | tr -d ' \n\r\t' | sed -n 's/.*"version":\([0-9]*\).*/\1/p')
		is_uint "$v" || v=0
		cred_result "$id" write created "$v" ""
		return 0
	fi
	data=
	case "$out" in
	*'check-and-set parameter did not match'*)
		# Created by someone else between the metadata read and the write.
		meta "$path"
		if [ "$M_STATE" = exists ]; then
			exists_result "$id" write "$path" "$@"
			return
		fi
		cred_result "$id" write error "$M_VERSION" "CAS mismatch on $OB_KV_MOUNT/$path, then state $M_STATE"
		return 1
		;;
	esac
	cred_result "$id" write error 0 "write $OB_KV_MOUNT/$path: $(errtext "$out")"
	return 1
}

# check_cred <id> <path> [<key=spec>...]
check_cred() {
	cid=$1
	cpath=$2
	shift 2
	meta "$cpath"
	case "$M_STATE" in
	error) cred_result "$cid" check error 0 "$M_ERR"; return 1 ;;
	exists) exists_result "$cid" check "$cpath" "$@" ;;
	*) cred_result "$cid" check "$M_STATE" "$M_VERSION" ""; return 0 ;;
	esac
}

# meta_exists <path>: sets E_STATE (present | absent | error) and E_ERR from
# a read of the entry's metadata (present also for an entry without a live
# version, e.g. metadata only or every version deleted).
meta_exists() {
	E_ERR=
	if out=$(BAO_TOKEN="$TOKEN" bao read -format=json "$OB_KV_MOUNT/metadata/$1" 2>&1); then
		E_STATE=present
	else
		case "$out" in
		*'No value found at'*) E_STATE=absent ;;
		*) E_STATE=error; E_ERR=$(errtext "$out") ;;
		esac
	fi
}

# delete_cred <id> <path>: metadata and every version of the entry.
delete_cred() {
	did=$1
	dpath=$2
	meta_exists "$dpath"
	case "$E_STATE" in
	error) cred_result "$did" delete error 0 "read $OB_KV_MOUNT/metadata/$dpath: $E_ERR"; return 1 ;;
	absent) cred_result "$did" delete missing 0 ""; return 0 ;;
	esac
	if ! out=$(BAO_TOKEN="$TOKEN" bao kv metadata delete -mount="$OB_KV_MOUNT" "$dpath" 2>&1); then
		cred_result "$did" delete error 0 "delete $OB_KV_MOUNT/metadata/$dpath: $(errtext "$out")"
		return 1
	fi
	meta_exists "$dpath"
	if [ "$E_STATE" != absent ]; then
		cred_result "$did" delete error 0 "$OB_KV_MOUNT/metadata/$dpath is still there after the delete${E_ERR:+ ($E_ERR)}"
		return 1
	fi
	cred_result "$did" delete removed 0 ""
}

# list_keys <prefix>: sets L_STATE (ok | empty | error), L_ERR, and writes
# the key names under <prefix> (one per line; folders end in /) to
# $OB_WORK_DIR/list. Names are paths, not values.
list_keys() {
	L_ERR=
	: >"$OB_WORK_DIR/list"
	if out=$(BAO_TOKEN="$TOKEN" bao kv list -mount="$OB_KV_MOUNT" -format=json "$1" 2>&1); then
		# A JSON array, one element per line: "name" or "name/".
		printf '%s\n' "$out" | sed -n 's/^ *"\(.*\)",\{0,1\} *$/\1/p' >"$OB_WORK_DIR/list"
		if [ -s "$OB_WORK_DIR/list" ]; then L_STATE=ok; else L_STATE=empty; fi
		return
	fi
	case "$(printf '%s' "$out" | tr -d ' \n\r\t')" in
	'{}' | *'Novaluefoundat'*) L_STATE=empty ;;
	*) L_STATE=error; L_ERR=$(errtext "$out") ;;
	esac
}

# purge_prefix <cluster_id>/<layer>: every entry left under the prefix.
PURGE_MAX=10000
purge_prefix() {
	pfx=$1
	removed=0
	perr=
	visited=0
	printf '%s\n' "$pfx" >"$OB_WORK_DIR/queue"
	while [ -s "$OB_WORK_DIR/queue" ]; do
		dir=$(head -n 1 "$OB_WORK_DIR/queue")
		sed -i '1d' "$OB_WORK_DIR/queue"
		visited=$((visited + 1))
		if [ "$visited" -gt "$PURGE_MAX" ]; then
			perr="more than $PURGE_MAX folders under $pfx"
			break
		fi
		list_keys "$dir"
		case "$L_STATE" in
		empty) continue ;;
		error) perr="list $OB_KV_MOUNT/metadata/$dir: $L_ERR"; break ;;
		esac
		while IFS= read -r name || [ -n "$name" ]; do
			base=${name%/}
			if ! is_segment "$base"; then
				perr="$OB_KV_MOUNT/metadata/$dir holds an entry whose name is not of [A-Za-z0-9._-] ($(printf '%s' "$name" | cut -c1-64)); delete it by hand with bao kv metadata delete"
				break 2
			fi
			if [ "$name" != "$base" ]; then
				printf '%s\n' "$dir/$base" >>"$OB_WORK_DIR/queue"
				continue
			fi
			if ! out=$(BAO_TOKEN="$TOKEN" bao kv metadata delete -mount="$OB_KV_MOUNT" "$dir/$base" 2>&1); then
				perr="delete $OB_KV_MOUNT/metadata/$dir/$base: $(errtext "$out")"
				break 2
			fi
			removed=$((removed + 1))
		done <"$OB_WORK_DIR/list"
	done
	rm -f "$OB_WORK_DIR/queue" "$OB_WORK_DIR/list"
	if [ -z "$perr" ]; then
		list_keys "$pfx"
		case "$L_STATE" in
		empty) ;;
		error) perr="list $OB_KV_MOUNT/metadata/$pfx after the purge: $L_ERR" ;;
		*) perr="$OB_KV_MOUNT/metadata/$pfx still lists $(tr '\n' ' ' <"$OB_WORK_DIR/list" | cut -c1-200) after the purge (written meanwhile?)" ;;
		esac
		rm -f "$OB_WORK_DIR/list"
	fi
	if [ -n "$perr" ]; then
		result "{\"kind\":\"purge\",\"prefix\":\"$(jstr "$pfx")\",\"state\":\"error\",\"removed\":$removed,\"error\":\"$(jstr "$perr")\"}"
		return 1
	fi
	result "{\"kind\":\"purge\",\"prefix\":\"$(jstr "$pfx")\",\"state\":\"ok\",\"removed\":$removed,\"error\":\"\"}"
}

run_plan() {
	rc=0
	while IFS= read -r line || [ -n "$line" ]; do
		case "$line" in '' | '#'*) continue ;; esac
		# shellcheck disable=SC2086
		set -- $line
		action=$1
		shift
		case "$action" in
		write) write_cred "$@" || rc=1 ;;
		delete) delete_cred "$@" || rc=1 ;;
		# After the deletes; skipped when one failed (the entry would count as
		# a leftover and hide the failure).
		purge) if [ "$rc" -eq 0 ]; then purge_prefix "$@" || rc=1; fi ;;
		*) check_cred "$@" || rc=1 ;;
		esac
	done <"$OB_PLAN_FILE"
	[ "$rc" -eq 0 ] || die "one or more credentials failed (see the credential results)"
}

check_params
[ "$OP" = probe ] || check_plan
probe
[ "$OP" = probe ] || run_plan
exit 0
