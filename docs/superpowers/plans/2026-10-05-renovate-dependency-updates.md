# Self-hosted Renovate Dependency Updates Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a self-hosted Renovate setup to enterprise-rag that produces one weekly grouped dependency PR, separate major-update PRs and immediate CVE PRs across Python, npm, Go, Docker, Helm, GitHub Actions and embedded tool pins.

**Architecture:** A single `renovate.json5` at the repo root holds all Renovate repo config (managers, three PR lanes, custom regex managers). A scheduled workflow `.github/workflows/renovate.yml` runs the official Renovate container with a short-lived GitHub App token. A second workflow validates the config on PRs. A local script runs Renovate in `--platform=local` dry-run mode so every config change is tested on this machine before anything touches GitHub.

**Tech Stack:** Renovate 44.133.0 (`ghcr.io/renovatebot/renovate`), `renovatebot/github-action` v46.3.7, `actions/create-github-app-token` v3.2.0, `step-security/harden-runner` v2.21.1, JSON5, bash, jq.

**Spec:** `docs/superpowers/specs/2026-10-05-renovate-dependency-updates-design.md`

## Global Constraints

- Nothing leaves this machine. No `git push`, no `gh` write calls, no GitHub App creation, no repo settings changes. Steps that need GitHub are written as instructions for the user (Task 11).
- All work on branch `renovate-poc` of `/home/mramotow/repos/rag-okf-example/enterprise-rag`. Commit after every task with `git commit -s` (DCO sign-off required by `CONTRIBUTING.md`) and the trailer `Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`.
- Every GitHub Action `uses:` is pinned to a full commit SHA with a `# vX.Y.Z` comment, same style as the existing workflows. Existing pins to reuse verbatim:
  - `step-security/harden-runner@e14015d583714f6e62063499dc959a02595150a1 # v2.21.1`
  - `actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1`
  - New: `renovatebot/github-action@230ce922b08968d0a4f6f70f295601daff09ef1d # v46.3.7`
  - New: `actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1 # v3.2.0`
- Renovate images (resolved 2026-10-05):
  - full: `ghcr.io/renovatebot/renovate:44.133.0-full@sha256:f8172bfd142f957ae5dd9cec535d2cceeb784e9fd6c1e708d2f57bbab1de0990`
  - slim: `ghcr.io/renovatebot/renovate:44.133.0@sha256:05c512c35c764ef6a179e69c3b30567eca254d67f13a0143479fe3c84852c67a`
- Local Renovate CLI is installed at `/tmp/renovate-cli/node_modules/.bin/renovate` (v44.133.0). If missing: `mkdir -p /tmp/renovate-cli && cd /tmp/renovate-cli && npm init -y >/dev/null && npm install --no-audit --no-fund renovate@44.133.0` (takes ~8 min behind the proxy). Export `RENOVATE_BIN=/tmp/renovate-cli/node_modules/.bin/renovate` for every test step.
- Lookup/full dry runs need `export GITHUB_COM_TOKEN=$(gh auth token)` (read-only use) or github-releases lookups are rate limited.
- Docker daemon on this machine cannot reach ghcr.io (no proxy configured); use the npm-installed CLI, not `docker run`, for local tests.
- Renovate v44 uses `managerFilePatterns` (regex strings wrapped in `/…/`), not the deprecated `fileMatch`. The validator runs with `--strict` and fails on anything needing migration.
- Config file comments: JSON5 `//` comments are allowed and encouraged; every non-obvious rule gets one.
- Workflow files keep the repo's existing style: `---` header, `name: "Sec :: …"`, explanatory comment block, `permissions: contents: read` at top level, harden-runner as first step, `persist-credentials: false` on checkout, `timeout-minutes` on every job, `defaults.run.shell: bash`.

## Review Focus

1. A Dockerfile where `ARG python_version=` and `ARG python_image_digest=` are more than 600 characters apart, or in reverse order, would silently be skipped by the custom Python-base manager and keep a stale digest. Test in Task 6 asserts exactly 24 matches, which fails if any file drops out.
2. `docker:pinDigests` from `config:best-practices` would rewrite Helm `tag:` values to `8.2.2@sha256:…`, which the charts do not render. Task 4 adds the `pinDigests: false` rule for `helm-values`, `kubernetes`, `helmv3` and asserts no `pinDigest` update is proposed for those managers in Task 10.
3. A `# renovate:` comment followed by a line whose value starts with a non-digit (e.g. `image: "busybox:1.36"`) must capture `1.36`, not `busybox`. Task 7 test asserts the busybox dep has `currentValue: "1.36"`.
4. The weekly group must not absorb `major` updates or vulnerability fixes. Task 5 asserts the set of branch names from a lookup dry run is `renovate/weekly` plus `renovate/major-*` only.
5. The shellcheck download is verified by `SHELLCHECK_SHA256`; a Renovate bump of `SHELLCHECK_VERSION` without the checksum would break CI. The plan deliberately does not annotate shellcheck (Task 8 step 7 documents it) and Task 10 asserts no update targets `shellcheck.yml`.

---

### Task 1: Local dry-run harness and config skeleton

**Files:**
- Create: `.github/scripts/renovate-local.sh`
- Create: `renovate.json5`
- Modify: `.gitignore` (append `.renovate-local/`)

**Interfaces:**
- Produces: `.github/scripts/renovate-local.sh <validate|extract|lookup|full> [includePath…]`. `validate` exits non-zero on invalid config. The other modes write `.renovate-local/<mode>.jsonl` (JSON lines, one Renovate log record per line, non-JSON lines stripped) and print a `manager<TAB>fileCount<TAB>depCount` table. Later tasks query the `.jsonl` with `jq`.
- Log records used by later tasks: `msg=="Extracted dependencies"` carries `.packageFiles.<manager>[]` with `.packageFile` and `.deps[]`; `msg=="Dependency extraction complete"` carries `.stats.managers`; `msg=="packageFiles with updates"` (lookup/full only) carries `.config.<manager>[].deps[].updates[]` with `branchName`, `updateType`, `newValue`, `newDigest`.

- [ ] **Step 1: Write the harness script**

```bash
#!/usr/bin/env bash
# Copyright (C) 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0
#
# Run Renovate against this checkout without touching GitHub.
#
#   .github/scripts/renovate-local.sh validate            # schema + migration check of renovate.json5
#   .github/scripts/renovate-local.sh extract [paths…]    # which files/deps each manager detects (offline)
#   .github/scripts/renovate-local.sh lookup  [paths…]    # + version/digest lookups (network, read-only)
#   .github/scripts/renovate-local.sh full    [paths…]    # + compute file changes in memory (nothing written)
#
# Output: .renovate-local/<mode>.jsonl (JSON log lines) and a per-manager summary on stdout.
# Query examples:
#   jq -r 'select(.msg=="Extracted dependencies") | .packageFiles | keys[]' .renovate-local/extract.jsonl
#   jq -r 'select(.msg=="packageFiles with updates") | .. | .branchName? // empty' .renovate-local/lookup.jsonl | sort -u
#
# Needs the Renovate CLI: `npm install -g renovate@44.133.0`, or set RENOVATE_BIN to its path.
# lookup/full need GITHUB_COM_TOKEN (e.g. `export GITHUB_COM_TOKEN=$(gh auth token)`) for GitHub lookups.
set -euo pipefail

mode=${1:-}
case "$mode" in
  validate|extract|lookup|full) ;;
  *) echo "usage: $0 validate|extract|lookup|full [includePath…]" >&2; exit 2 ;;
esac
shift

repo=$(git -C "$(dirname "$0")" rev-parse --show-toplevel)
bin=${RENOVATE_BIN:-renovate}
cd "$repo"

if [[ "$mode" == validate ]]; then
  exec "${bin}-config-validator" --strict renovate.json5
fi

out="$repo/.renovate-local"
mkdir -p "$out"
log="$out/$mode.jsonl"

if [[ $# -gt 0 ]]; then
  export RENOVATE_INCLUDE_PATHS
  RENOVATE_INCLUDE_PATHS=$(IFS=,; echo "$*")
fi

set +e
LOG_LEVEL=${LOG_LEVEL:-debug} LOG_FORMAT=json \
  RENOVATE_PLATFORM=local RENOVATE_DRY_RUN="$mode" \
  "$bin" >"$log.raw" 2>&1
status=$?
set -e

# Drop non-JSON noise (node warnings) so jq can read the file.
grep '^{' "$log.raw" >"$log" || true
rm -f "$log.raw"

echo "renovate exit code: $status  log: $log"
echo "errors/warnings:"
jq -r 'select(.level >= 40) | "  [\(.level)] \(.msg)\(if .err then " | " + (.err.message // "") else "" end)"' "$log" | sort | uniq -c | sort -rn | head -20
echo
printf 'manager\tfiles\tdeps\n'
jq -r 'select(.msg=="Dependency extraction complete") | .stats.managers | to_entries[] | "\(.key)\t\(.value.fileCount)\t\(.value.depCount)"' "$log"
exit "$status"
```

Save as `.github/scripts/renovate-local.sh` and `chmod +x .github/scripts/renovate-local.sh`.

- [ ] **Step 2: Write the config skeleton**

`renovate.json5`:

```json5
// Renovate configuration for enterprise-rag.
//
// Design: docs/superpowers/specs/2026-10-05-renovate-dependency-updates-design.md
// Runner: .github/workflows/renovate.yml (self-hosted, weekly) and
//         .github/workflows/renovate-validate.yml (validates this file on PRs).
// Local check before pushing: .github/scripts/renovate-local.sh validate|extract|lookup
// Reference: https://docs.renovatebot.com/configuration-options/
{
  $schema: "https://docs.renovatebot.com/renovate-schema.json",
  extends: ["config:best-practices"],
}
```

- [ ] **Step 3: Append to `.gitignore`**

Add after the `.venv/` line (line 67):

```
# Local Renovate dry-run logs (.github/scripts/renovate-local.sh)
.renovate-local/
```

- [ ] **Step 4: Run validate and extract**

```bash
export RENOVATE_BIN=/tmp/renovate-cli/node_modules/.bin/renovate
.github/scripts/renovate-local.sh validate
.github/scripts/renovate-local.sh extract
```

Expected: validator prints `INFO: Config validated successfully against 1 file(s)`. Extract prints a table with exactly these managers and counts (baseline measured on 2026-10-05):

```
docker-compose	13	11
dockerfile	69	222
github-actions	7	43
gomod	1	99
helm-values	12	42
helmv3	4	5
npm	16	158
pep621	27	738
terraform	1	2
```

`pip_requirements` is absent because `config:best-practices` ignores `**/tests/**`; `terraform` is present because of `src/edp/terraform/provider.tf`. Both are fixed in Task 2. Warnings `Unknown error fetching default owner preset` are normal for `--platform=local`.

- [ ] **Step 5: Commit**

```bash
git add .github/scripts/renovate-local.sh renovate.json5 .gitignore
git commit -s -m "ci(renovate): add config skeleton and local dry-run harness

renovate-local.sh runs Renovate in --platform=local dry-run mode so every
config change can be checked on a developer machine before it reaches GitHub.

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 2: Core settings and manager allowlist

**Files:**
- Modify: `renovate.json5`

**Interfaces:**
- Produces: top-level keys `enabledManagers`, `ignorePaths`, `schedule`, `timezone`, `labels`, `semanticCommit*`, `minimumReleaseAge`, `pr*Limit`, `rebaseWhen`, `dependencyDashboard*`, `automergeType`, `platformAutomerge`, `lockFileMaintenance`, `pep621`, `kubernetes`, `vulnerabilityAlerts`, `osvVulnerabilityAlerts`. Task 3 adds `packageRules`, Tasks 6–8 add `customManagers`.

- [ ] **Step 1: Replace `renovate.json5` body**

Keep the header comments from Task 1; replace the object with:

```json5
{
  $schema: "https://docs.renovatebot.com/renovate-schema.json",

  // config:best-practices = config:recommended + digest pinning for Docker and
  // GitHub Actions + config migration + abandonment detection.
  // :gitSignOff adds the DCO trailer that CONTRIBUTING.md requires.
  extends: [
    "config:best-practices",
    ":dependencyDashboard",
    ":gitSignOff",
    ":semanticCommits",
    "helpers:pinGitHubActionDigests",
  ],

  // ---------------------------------------------------------------------------
  // Scope
  // ---------------------------------------------------------------------------
  // Explicit allowlist: a manager that is not listed never runs, even if
  // Renovate adds new ones. terraform is deliberately absent
  // (src/edp/terraform is a sample, not a shipped artefact).
  enabledManagers: [
    "github-actions",
    "pep621",
    "pip_requirements",
    "npm",
    "gomod",
    "dockerfile",
    "docker-compose",
    "helm-values",
    "helmv3",
    "kubernetes",
    "custom.regex",
  ],
  // config:recommended ignores **/tests/** and **/test/**. We want
  // src/tests/**/requirements.txt managed, so the list is restated without them.
  ignorePaths: [
    "**/node_modules/**",
    "**/bower_components/**",
    "**/vendor/**",
    "**/__fixtures__/**",
    "**/.tox/**",
    "**/.venv/**",
  ],
  // Helm templates and Ansible role files carry plain `image: name:tag` lines.
  kubernetes: {
    managerFilePatterns: [
      "/^deployment/components/[^/]+/templates/.+\\.ya?ml$/",
      "/^deployment/roles/.+\\.ya?ml$/",
    ],
  },
  // ~500 of ~700 pyproject specifiers are `==` pins. "bump" moves the pin and
  // regenerates uv.lock in the same commit instead of leaving pins frozen.
  pep621: {
    rangeStrategy: "bump",
  },

  // ---------------------------------------------------------------------------
  // Cadence and PR shape
  // ---------------------------------------------------------------------------
  timezone: "UTC",
  schedule: ["before 6am on monday"],
  // Weekly lock refresh picks up transitive updates that no direct pin covers.
  // Grouped into the weekly PR by the packageRules below.
  lockFileMaintenance: {
    enabled: true,
    schedule: ["before 6am on monday"],
  },
  // Fresh releases are the supply-chain attack vector (maintainer account
  // takeover). Three days lets a malicious release be yanked before we pull
  // it. Digest-only updates and vulnerability fixes are exempt (see rules).
  minimumReleaseAge: "3 days",
  prConcurrentLimit: 10,
  prHourlyLimit: 0,
  branchConcurrentLimit: 0,
  rebaseWhen: "behind-base-branch",
  labels: ["dependencies", "renovate"],
  semanticCommitType: "build",
  semanticCommitScope: "deps",
  dependencyDashboardTitle: "Dependency Dashboard (Renovate)",
  // Automerge itself is OFF by default; the runner workflow flips it via the
  // RENOVATE_AUTOMERGE environment variable. These two settings only define
  // HOW an automerge happens when it is enabled, so no config PR is needed then.
  automergeType: "pr",
  platformAutomerge: true,

  // ---------------------------------------------------------------------------
  // Security lane: CVE fixes bypass schedule, grouping and cooldown
  // ---------------------------------------------------------------------------
  // Needs the Dependabot alerts feed (GitHub App permission
  // "vulnerability alerts: read"); OSV covers ecosystems GitHub does not.
  vulnerabilityAlerts: {
    enabled: true,
    labels: ["dependencies", "renovate", "security"],
    schedule: ["at any time"],
    minimumReleaseAge: null,
    prPriority: 10,
    groupName: null,
  },
  osvVulnerabilityAlerts: true,
}
```

- [ ] **Step 2: Validate**

```bash
.github/scripts/renovate-local.sh validate
```

Expected: `Config validated successfully`. If it reports `Config migration necessary`, the offending key was renamed in Renovate 44; fix the key, do not downgrade.

- [ ] **Step 3: Extract and assert managers**

```bash
.github/scripts/renovate-local.sh extract
jq -r 'select(.msg=="Extracted dependencies") | .packageFiles | keys | join(",")' .renovate-local/extract.jsonl
jq -r 'select(.msg=="Extracted dependencies") | .packageFiles.pip_requirements[].packageFile' .renovate-local/extract.jsonl
jq -r 'select(.msg=="Extracted dependencies") | .packageFiles.kubernetes[] | "\(.packageFile): \([.deps[].depName] | join(", "))"' .renovate-local/extract.jsonl | head -20
```

Expected:
- keys: `docker-compose,dockerfile,github-actions,gomod,helm-values,helmv3,kubernetes,npm,pep621,pip_requirements` (no `terraform`).
- pip_requirements lists 7 files, all under `src/tests/`, none under `.tox`.
- kubernetes lists files under `deployment/components/*/templates/` and/or `deployment/roles/`. If the count is 0, print warnings with `jq -r 'select(.level>=40 and (.msg|test("kubernetes|yaml|parse";"i")))' .renovate-local/extract.jsonl` and narrow `managerFilePatterns` to the files that contain literal `image:` lines (`grep -rlE '^\s*(-\s*)?image:\s*["'"'"']?[a-z0-9./_-]+:[A-Za-z0-9._-]+' deployment/components/*/templates deployment/roles`). Record the resulting file count in the commit message.

- [ ] **Step 4: Commit**

```bash
git add renovate.json5
git commit -s -m "ci(renovate): core settings, manager allowlist, security lane

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 3: PR lanes and base-image policy (packageRules)

**Files:**
- Modify: `renovate.json5`

**Interfaces:**
- Produces: `packageRules` array. Branch names later tasks assert: `renovate/weekly` for the weekly group; `renovate/major-<slug>` for majors; `renovate/spacy` for the spaCy pair.

- [ ] **Step 1: Add `packageRules` after `osvVulnerabilityAlerts`**

```json5
  // ---------------------------------------------------------------------------
  // PR lanes. Later rules override earlier ones.
  // ---------------------------------------------------------------------------
  packageRules: [
    // Lane 1: everything non-breaking lands in ONE weekly PR.
    {
      description: "Weekly grouped PR for all minor/patch/digest/pin/lockfile updates",
      matchPackageNames: ["*"],
      matchUpdateTypes: ["minor", "patch", "pin", "digest", "pinDigest", "lockFileMaintenance"],
      groupName: "weekly dependencies",
      groupSlug: "weekly",
    },
    // Lane 2: majors are one PR per dependency so a breaking change never
    // blocks the weekly batch. Branch prefix makes them easy to filter.
    {
      description: "Major updates: separate PR per dependency",
      matchPackageNames: ["*"],
      matchUpdateTypes: ["major"],
      additionalBranchPrefix: "major-",
      prPriority: -1,
    },

    // Digest-only updates have no release date; cooldown would stall them.
    {
      description: "No cooldown for digest pinning",
      matchUpdateTypes: ["digest", "pinDigest", "pin"],
      minimumReleaseAge: null,
    },

    // Helm charts and k8s manifests do not render image@digest; keep tags only.
    {
      description: "No digest pinning in Helm values / templates",
      matchManagers: ["helm-values", "kubernetes", "helmv3"],
      pinDigests: false,
    },

    // Debian packages pinned in Dockerfiles (openssl=3.5.7-1~deb13u3 …) are
    // resolved against trixie main. The security pocket only publishes
    // Packages.xz, which the deb datasource cannot read, so security-only
    // builds appear here at the next point release.
    {
      description: "Debian trixie registry for apt pins",
      matchDatasources: ["deb"],
      registryUrls: ["https://deb.debian.org/debian?suite=trixie&components=main&binaryArch=amd64"],
    },

    // Base language images: patch and digest only. python 3.12 needs
    // requires-python changes in 29 pyprojects, node/go toolchain bumps are
    // coordinated by hand. The go.mod `go` directive follows the same rule so
    // golang:1.25.x and `go 1.25.x` move together in the weekly PR.
    {
      description: "python/node/go: no major or minor bumps",
      matchDepNames: ["python", "node", "golang", "go"],
      matchUpdateTypes: ["major", "minor"],
      enabled: false,
    },

    // spaCy model releases must match the spacy major.minor; keep the pair in
    // one dedicated PR so a reviewer sees both lines.
    {
      description: "spaCy library and model move together",
      matchPackageNames: ["spacy", "explosion/spacy-models"],
      groupName: "spacy",
      groupSlug: "spacy",
    },
  ],
```

- [ ] **Step 2: Validate**

```bash
.github/scripts/renovate-local.sh validate
```

Expected: `Config validated successfully`.

- [ ] **Step 3: Lookup dry run on a small slice and assert branch names**

```bash
export GITHUB_COM_TOKEN=$(gh auth token)
.github/scripts/renovate-local.sh lookup '.github/workflows/**' 'src/gmc/go.mod' 'src/ui/apps/chatqna/Dockerfile'
jq -r 'select(.msg=="packageFiles with updates") | .config | .. | objects | select(has("branchName")) | "\(.branchName)\t\(.updateType)"' .renovate-local/lookup.jsonl | sort | uniq -c
```

Expected: every non-major row has branch `renovate/weekly`; every `major` row has a branch starting `renovate/major-`; no other branch names. If `lockFileMaintenance` shows its own branch `renovate/lock-file-maintenance`, add `groupName: "weekly dependencies", groupSlug: "weekly"` inside the `lockFileMaintenance` object and re-run.

- [ ] **Step 4: Assert base-image policy**

```bash
jq -r 'select(.msg=="packageFiles with updates") | .config | .. | objects | select(.depName=="node" or .depName=="go" or .depName=="python") | "\(.depName) \(.currentValue) -> \([.updates[]? | "\(.updateType):\(.newValue)"] | join(" "))"' .renovate-local/lookup.jsonl | sort -u
```

Expected: `node 20-alpine` offers only `pinDigest`/`digest`/`patch` entries, never `major`/`minor`; `go 1.25.12` offers at most a `patch`; `python 3.12.14` (setup-python) offers at most a `patch`.

- [ ] **Step 5: Commit**

```bash
git add renovate.json5
git commit -s -m "ci(renovate): weekly/major/security lanes and base-image policy

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 4: Verify Helm/compose/deb behaviour with a lookup on `deployment/` and one Dockerfile

**Files:**
- Modify: `renovate.json5` only if an assertion fails.

**Interfaces:**
- Consumes: rules from Task 3.

- [ ] **Step 1: Lookup on deployment and the edp Dockerfile**

```bash
.github/scripts/renovate-local.sh lookup 'deployment/**' 'src/edp/Dockerfile'
```

- [ ] **Step 2: Assert no digest pinning in Helm/k8s**

```bash
jq -r 'select(.msg=="packageFiles with updates") | .config | to_entries[] | select(.key=="helm-values" or .key=="kubernetes" or .key=="helmv3") | .value[] | .deps[] | .updates[]? | select(.updateType=="pinDigest" or .updateType=="digest") | "FAIL \(.branchName)"' .renovate-local/lookup.jsonl
```

Expected: no output. Any `FAIL` line means the `pinDigests: false` rule did not apply; check the manager name spelling in the rule.

- [ ] **Step 3: Assert deb packages resolve**

```bash
jq -c 'select(.msg=="packageFiles with updates") | .config.dockerfile[]? | .deps[] | select(.datasource=="deb") | {depName,currentValue,registryUrl,skipReason,warnings:[.warnings[]?.message],updates:[.updates[]?.newValue]}' .renovate-local/lookup.jsonl
```

Expected: `openssl`, `libssl3t64`, `openssl-provider-legacy` show `registryUrl` set to the trixie URL, `skipReason: null`, empty `warnings`. `updates` is empty while `3.5.7-1~deb13u3` is current in trixie main. `qpdf` shows `skipReason: "unspecified-version"` (unpinned, intentionally ignored).

- [ ] **Step 4: Assert compose images are detected and `latest` tags are skipped, not bumped**

```bash
jq -r 'select(.msg=="packageFiles with updates") | .config["docker-compose"][]? | "\(.packageFile): " + ([.deps[] | "\(.depName):\(.currentValue // "-")\(if .skipReason then " [" + .skipReason + "]" else "" end)"] | join(", "))' .renovate-local/lookup.jsonl
```

Expected: external images (`public.ecr.aws/q9t5s3a7/vllm-cpu-release-repo`, `mongo`, `postgres`, `redis/redis-stack`, `chrislusf/seaweedfs`) have `currentValue` set; first-party `erag/*:latest` style entries show a `skipReason` or are absent. No `latest` value receives a `newValue`.

- [ ] **Step 5: Commit if anything changed**

```bash
git add renovate.json5
git commit -s -m "ci(renovate): adjust manager scoping after deployment dry run

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

Skip the commit if no file changed.

---

### Task 5: Custom manager for `src/tox.ini` requires

**Files:**
- Modify: `renovate.json5`
- Read: `src/tox.ini:4-8`

**Interfaces:**
- Produces: `customManagers` array (first entry). Dep names `tox`, `tox-uv`, `uv` on datasource `pypi`, same names Task 8 uses in `val-unit-tests.yml`, so both files land in the same branch.

- [ ] **Step 1: Add `customManagers` after `packageRules`**

```json5
  // ---------------------------------------------------------------------------
  // Custom managers (regex). Each one is tested by .github/scripts/renovate-local.sh extract.
  // ---------------------------------------------------------------------------
  customManagers: [
    // src/tox.ini [tox] requires. Must stay equal to UV_VERSION/TOX_VERSION/
    // TOX_UV_VERSION in .github/workflows/val-unit-tests.yml or tox provisions a
    // second copy of itself; same depNames there, so Renovate updates both files
    // in one branch.
    {
      customType: "regex",
      description: "tox/tox-uv/uv pins in src/tox.ini",
      managerFilePatterns: ["/^src/tox\\.ini$/"],
      matchStrings: ["\\n\\s+(?<depName>tox|tox-uv|uv)==(?<currentValue>\\d+\\.\\d+\\.\\d+)"],
      datasourceTemplate: "pypi",
    },
  ],
```

- [ ] **Step 2: Validate and extract**

```bash
.github/scripts/renovate-local.sh validate
.github/scripts/renovate-local.sh extract src/tox.ini
jq -c 'select(.msg=="Extracted dependencies") | .packageFiles["custom.regex"][] | {f:.packageFile, deps:[.deps[] | {depName,currentValue,datasource}]}' .renovate-local/extract.jsonl
```

Expected: one entry for `src/tox.ini` with exactly `tox 4.30.2`, `tox-uv 1.28.0`, `uv 0.8.17`, all `datasource: "pypi"`.

- [ ] **Step 3: Commit**

```bash
git add renovate.json5
git commit -s -m "ci(renovate): manage tox/tox-uv/uv pins in src/tox.ini

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 6: Custom manager for the ARG-split Python base image

**Files:**
- Modify: `renovate.json5`
- Read: `src/edp/Dockerfile:5-11` (representative of all 24)

**Interfaces:**
- Produces: `custom.regex` deps named `python`, datasource `docker`, `currentValue: "3.11-slim-trixie"`, `currentDigest` from the `ARG python_image_digest` line. The base-image rule from Task 3 (`matchDepNames: ["python"]`) already blocks major/minor for it.

- [ ] **Step 1: Append to `customManagers`**

```json5
    // 24 Dockerfiles build the base image reference from three ARGs:
    //   ARG python_version=3.11
    //   ARG python_image_version=${python_version}-slim-trixie
    //   ARG python_image_digest=sha256:…
    //   FROM python:${python_image_version}@${python_image_digest}
    // The dockerfile manager skips this (contains-variable). This manager reads
    // the version and digest ARGs (always in that order, <600 chars apart) and
    // reconstructs the tag, so Renovate can refresh the digest in all 24 files
    // in one commit. Only digest updates apply: the version part is not a
    // capture group, and major/minor python bumps are disabled anyway.
    {
      customType: "regex",
      description: "python base image via ARG python_version + ARG python_image_digest",
      managerFilePatterns: ["/(^|/)Dockerfile$/"],
      matchStrings: [
        "ARG python_version=(?<pythonVersion>\\d+\\.\\d+)\\n[\\s\\S]{0,600}?ARG python_image_digest=(?<currentDigest>sha256:[a-f0-9]{64})",
      ],
      depNameTemplate: "python",
      datasourceTemplate: "docker",
      currentValueTemplate: "{{{pythonVersion}}}-slim-trixie",
      versioningTemplate: "docker",
    },
```

- [ ] **Step 2: Validate and extract**

```bash
.github/scripts/renovate-local.sh validate
.github/scripts/renovate-local.sh extract 'src/**/Dockerfile'
jq -r 'select(.msg=="Extracted dependencies") | .packageFiles["custom.regex"][] | .deps[] | select(.depName=="python") | "\(.currentValue) \(.currentDigest)"' .renovate-local/extract.jsonl | sort | uniq -c
```

Expected: exactly one line, `24 3.11-slim-trixie sha256:bab1b7ef4b450c81002278d035eff85ebe394ae94df904f7a3ba14f7e16e487b`. If the count is below 24, list the matched files with `jq -r '… | select(any(.deps[]; .depName=="python")) | .packageFile'` and diff against `grep -rl 'ARG python_image_digest' --include=Dockerfile src`; widen the `{0,600}` window if a file has a longer comment block between the two ARGs.

- [ ] **Step 3: Full dry run on one file to prove the digest replacement works**

```bash
export GITHUB_COM_TOKEN=$(gh auth token)
.github/scripts/renovate-local.sh full src/edp/Dockerfile
jq -r 'select(.msg=="packageFiles with updates") | .config["custom.regex"][]? | .deps[] | select(.depName=="python") | "\(.currentValue) updates=\([.updates[]? | "\(.updateType):\(.newValue):\(.newDigest // "-")"] | join(" "))"' .renovate-local/full.jsonl
jq -r 'select(.level>=40 and (.msg|test("replace|Could not";"i"))) | .msg' .renovate-local/full.jsonl
```

Expected: either `updates=` is empty (the pinned digest is still current for `python:3.11-slim-trixie`) or it contains a single `digest:3.11-slim-trixie:sha256:…` entry, and the second command prints nothing. If a `Could not find … replace` style message appears, replace the manager with the fallback form (digest line only, version hard-coded in config) and re-run:

```json5
      matchStrings: ["ARG python_image_digest=(?<currentDigest>sha256:[a-f0-9]{64})"],
      depNameTemplate: "python",
      datasourceTemplate: "docker",
      currentValueTemplate: "3.11-slim-trixie",
      versioningTemplate: "docker",
```

- [ ] **Step 4: Commit**

```bash
git add renovate.json5
git commit -s -m "ci(renovate): track digest of the ARG-split python base image

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 7: Generic `# renovate:` annotation manager and annotated pins in deployment, scripts, Dockerfiles

**Files:**
- Modify: `renovate.json5`
- Modify: `deployment/components/edp/values.yaml:65`
- Modify: `deployment/roles/app_inference_models/defaults/main.yaml:127`
- Modify: `deployment/roles/app_vector_databases/defaults/main.yaml:39-41`
- Modify: `deployment/update_images.sh:116`
- Modify: `src/comps/retrievers/impl/model_server/ovms/run_redis_and_seed.sh:18`
- Modify: `src/ui/apps/chatqna/Dockerfile:9`, `src/ui/apps/docsum/Dockerfile:9`, `src/ui/apps/audioqna/Dockerfile:9`
- Modify: `src/comps/vectorstores/impl/redis/redis-svs-vamana/Dockerfile:22`
- Modify: `src/comps/retrievers/impl/microservice/Dockerfile:14,51-52`

**Interfaces:**
- Produces: one regex manager that understands the comment grammar
  `# renovate: datasource=<ds> depName=<name> [versioning=<v>] [extractVersion=<re>] [registryUrl=<url>]`
  placed on the line directly above a `KEY: value`, `KEY=value` or `ARG KEY=value` line. The value may carry `@sha256:<digest>`. Task 8 reuses it for workflow files, Task 9 for the Renovate image itself.

- [ ] **Step 1: Append the manager to `customManagers`**

```json5
    // Generic annotation manager. Put this comment on the line above a pin:
    //   # renovate: datasource=docker depName=redis versioning=docker
    //   tag: "8.2.2"
    // Works for YAML keys, shell variables and Dockerfile ARGs; the value may
    // end in @sha256:<digest>. Optional fields: versioning, extractVersion,
    // registryUrl. Default versioning is semver-coerced; use versioning=docker
    // for image tags.
    {
      customType: "regex",
      description: "Pins annotated with a '# renovate:' comment on the previous line",
      managerFilePatterns: [
        "/^\\.github/workflows/[^/]+\\.ya?ml$/",
        "/^deployment/.+\\.ya?ml$/",
        "/\\.sh$/",
        "/(^|/)Dockerfile$/",
      ],
      matchStrings: [
        "# renovate: datasource=(?<datasource>[a-z0-9-]+) depName=(?<depName>[^\\s]+)(?: versioning=(?<versioning>[^\\s]+))?(?: extractVersion=(?<extractVersion>[^\\s]+))?(?: registryUrl=(?<registryUrl>[^\\s]+))?\\s*\\n[^\\n]*?[=:]\\s*[\"']?(?<currentValue>v?\\d[^\"'\\s@]*)(?:@(?<currentDigest>sha256:[a-f0-9]{64}))?",
      ],
      versioningTemplate: "{{#if versioning}}{{{versioning}}}{{else}}semver-coerced{{/if}}",
    },
```

- [ ] **Step 2: Annotate the seaweedfs chart version**

`deployment/components/edp/values.yaml` lines 63-66 become:

```yaml
seaweedfs:
  namespace: "seaweedfs"
  # renovate: datasource=helm depName=seaweedfs registryUrl=https://seaweedfs.github.io/seaweedfs/helm
  version: "4.37.0"
  repo: "https://seaweedfs.github.io/seaweedfs/helm"
```

- [ ] **Step 3: Annotate image tags in Ansible defaults**

`deployment/roles/app_inference_models/defaults/main.yaml` line 127 becomes:

```yaml
# renovate: datasource=docker depName=busybox versioning=docker
inference_topology_image: "busybox:1.36"
```

`deployment/roles/app_vector_databases/defaults/main.yaml` lines 39-41 become:

```yaml
    image:
      repository: "redis"
      # renovate: datasource=docker depName=redis versioning=docker
      tag: "8.2.2"
```

- [ ] **Step 4: Annotate shell script images**

`deployment/update_images.sh` line 116:

```bash
# renovate: datasource=docker depName=registry versioning=docker
REGISTRY_IMAGE=registry:2
```

`src/comps/retrievers/impl/model_server/ovms/run_redis_and_seed.sh` line 18:

```bash
# renovate: datasource=docker depName=redis versioning=docker
REDIS_IMAGE="redis:8.2.5-alpine"
```

- [ ] **Step 5: pnpm version in the three UI Dockerfiles**

In each of `src/ui/apps/chatqna/Dockerfile`, `src/ui/apps/docsum/Dockerfile`, `src/ui/apps/audioqna/Dockerfile`, replace lines 8-9:

```dockerfile
# Install pnpm
RUN corepack enable && corepack prepare pnpm@10.33.4 --activate
```

with:

```dockerfile
# Install pnpm
# renovate: datasource=npm depName=pnpm
ARG PNPM_VERSION=10.33.4
RUN corepack enable && corepack prepare "pnpm@${PNPM_VERSION}" --activate
```

- [ ] **Step 6: Redis source tag in the SVS Dockerfile**

`src/comps/vectorstores/impl/redis/redis-svs-vamana/Dockerfile` line 22 becomes:

```dockerfile
# renovate: datasource=github-tags depName=redis/redis
ARG REDIS_VERSION=8.2.2
```

- [ ] **Step 7: spaCy model release in the retrievers Dockerfile**

`src/comps/retrievers/impl/microservice/Dockerfile`: after line 14 (`ARG python_version`) insert:

```dockerfile
# Polish spaCy model, released on GitHub (not on PyPI). Its major.minor must
# match spacy in pyproject.toml; Renovate groups the two.
# renovate: datasource=github-releases depName=explosion/spacy-models extractVersion=^pl_core_news_sm-(?<version>.*)$
ARG SPACY_PL_MODEL_VERSION=3.8.0
```

and replace lines 51-52 (now shifted by four lines) with:

```dockerfile
# spaCy for Polish only, need to install the model via uv from GitHub release (not a standard PyPI package)
RUN uv pip install --no-cache "https://github.com/explosion/spacy-models/releases/download/pl_core_news_sm-${SPACY_PL_MODEL_VERSION}/pl_core_news_sm-${SPACY_PL_MODEL_VERSION}.tar.gz"
```

Check with `grep -n 'SPACY_PL_MODEL_VERSION\|^FROM' src/comps/retrievers/impl/microservice/Dockerfile` that the `ARG` sits after the single `FROM` and before the `RUN` that uses it (ARGs declared before `FROM` are not visible inside the stage).

- [ ] **Step 8: Validate and extract**

```bash
.github/scripts/renovate-local.sh validate
.github/scripts/renovate-local.sh extract 'deployment/**' 'src/**'
jq -r 'select(.msg=="Extracted dependencies") | .packageFiles["custom.regex"][] | .deps[] | select(.depName!="python" and .depName!="tox" and .depName!="tox-uv" and .depName!="uv") | "\(.datasource)\t\(.depName)\t\(.currentValue)\t\(.registryUrl // "-")\t\(.versioning // "-")"' .renovate-local/extract.jsonl | sort | uniq -c
```

Expected rows (count, datasource, depName, currentValue, registryUrl, versioning):

```
1 docker	busybox	1.36	-	docker
1 docker	redis	8.2.2	-	docker
1 docker	redis	8.2.5-alpine	-	docker
1 docker	registry	2	-	docker
1 github-releases	explosion/spacy-models	3.8.0	-	semver-coerced
1 github-tags	redis/redis	8.2.2	-	semver-coerced
1 helm	seaweedfs	4.37.0	https://seaweedfs.github.io/seaweedfs/helm	semver-coerced
3 npm	pnpm	10.33.4	-	semver-coerced
```

- [ ] **Step 9: Lookup the two non-trivial datasources**

```bash
export GITHUB_COM_TOKEN=$(gh auth token)
.github/scripts/renovate-local.sh lookup deployment/components/edp/values.yaml src/comps/retrievers/impl/microservice/Dockerfile
jq -c 'select(.msg=="packageFiles with updates") | .config["custom.regex"][]? | .deps[] | select(.depName=="seaweedfs" or .depName=="explosion/spacy-models") | {depName,currentValue,warnings:[.warnings[]?.message],updates:[.updates[]? | "\(.updateType):\(.newValue)"],branch:[.updates[]?.branchName]}' .renovate-local/lookup.jsonl
```

Expected: both deps have empty `warnings`. seaweedfs updates (if any) carry branch `renovate/weekly` or `renovate/major-…`; spacy-models updates carry branch `renovate/spacy`. If `explosion/spacy-models` shows `newValue` values like `en_core_web_sm-3.8.0`, the `extractVersion` did not apply: check the comment line has no trailing spaces and the regex `(?<version>.*)` group name is exactly `version`.

- [ ] **Step 10: Commit**

```bash
git add renovate.json5 deployment src/ui/apps/*/Dockerfile src/comps/vectorstores/impl/redis/redis-svs-vamana/Dockerfile src/comps/retrievers/impl/microservice/Dockerfile src/comps/retrievers/impl/model_server/ovms/run_redis_and_seed.sh
git commit -s -m "ci(renovate): annotate image, chart and tool pins outside package managers

Adds a '# renovate:' comment manager and annotates seaweedfs chart version,
busybox/redis/registry image tags, pnpm, the redis source tag and the Polish
spaCy model so Renovate tracks them.

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 8: Tool pins in scanner and unit-test workflows

**Files:**
- Modify: `.github/workflows/val-unit-tests.yml:30-34,73-84`
- Modify: `.github/workflows/bandit.yml:69-72`
- Modify: `.github/workflows/checkov.yml:65-66`
- Modify: `.github/workflows/ansible-lint.yml:58-59`

**Interfaces:**
- Consumes: annotation manager from Task 7 (same comment grammar).
- Natively detected already, do not annotate: `container:` image in val-unit-tests, `setup-python` `python-version`, trivy-action `version`, `setup-uv` `version` (becomes an expression below, replaced by the `UV_VERSION` annotation).

- [ ] **Step 1: val-unit-tests.yml: single source for uv/tox versions**

Job-level `env:` (lines 31-32) becomes:

```yaml
    env:
      DEBIAN_FRONTEND: noninteractive
      # Must equal [tox] requires in src/tox.ini, otherwise tox provisions a
      # second copy of itself in .tox/.tox on every run. Renovate bumps both.
      # renovate: datasource=pypi depName=uv
      UV_VERSION: "0.8.17"
      # renovate: datasource=pypi depName=tox
      TOX_VERSION: "4.30.2"
      # renovate: datasource=pypi depName=tox-uv
      TOX_UV_VERSION: "1.28.0"
```

Steps at lines 71-84 become:

```yaml
      - name: Install uv
        uses: astral-sh/setup-uv@c18668ad3cf93ea998bef934396af7bb5c839dc7 # v10.2.0
        with:
          version: ${{ env.UV_VERSION }}
          enable-cache: true
          cache-python: true
          cache-suffix: ${{ matrix.test-name }}

      - name: Install tox
        run: |
          uv tool install "tox==${TOX_VERSION}" --with "tox-uv==${TOX_UV_VERSION}" --with "uv==${UV_VERSION}"
          uv tool dir --bin >> "$GITHUB_PATH"
```

Delete the two-line comment `# Versions must match [tox] requires …` that preceded `Install uv` (it moved into `env:`).

- [ ] **Step 2: bandit.yml**

Lines 69-72 become:

```yaml
      - name: Install Bandit
        env:
          # renovate: datasource=pypi depName=bandit
          BANDIT_VERSION: "1.9.4"
        run: >-
          pip install --disable-pip-version-check
          "bandit[sarif,toml]==${BANDIT_VERSION}"
```

- [ ] **Step 3: checkov.yml**

Lines 65-66 become:

```yaml
      - name: Install Checkov
        env:
          # renovate: datasource=pypi depName=checkov
          CHECKOV_VERSION: "3.3.16"
        run: pip install --disable-pip-version-check "checkov==${CHECKOV_VERSION}"
```

- [ ] **Step 4: ansible-lint.yml**

Lines 58-59 become:

```yaml
      - name: Install ansible-lint
        env:
          # renovate: datasource=pypi depName=ansible-lint
          ANSIBLE_LINT_VERSION: "26.8.0"
        run: pip install --disable-pip-version-check "ansible-lint==${ANSIBLE_LINT_VERSION}"
```

- [ ] **Step 5: YAML sanity check**

```bash
python3 - <<'EOF'
import yaml, glob
for f in sorted(glob.glob(".github/workflows/*.yml")):
    yaml.safe_load(open(f)); print("ok", f)
EOF
```

Expected: `ok` for every file.

- [ ] **Step 6: Extract and assert**

```bash
.github/scripts/renovate-local.sh extract '.github/workflows/**' src/tox.ini
jq -r 'select(.msg=="Extracted dependencies") | .packageFiles["custom.regex"][] | .deps[] | "\(.depName)\t\(.currentValue)"' .renovate-local/extract.jsonl | sort | uniq -c
jq -r 'select(.msg=="Extracted dependencies") | .packageFiles["github-actions"][] | .deps[] | select(.depType=="uses-with") | "\(.packageFile)\t\(.depName)\t\(.currentValue)"' .renovate-local/extract.jsonl
```

Expected first command (count, depName, value): `1 ansible-lint 26.8.0`, `1 bandit 1.9.4`, `1 checkov 3.3.16`, `2 tox 4.30.2`, `2 tox-uv 1.28.0`, `2 uv 0.8.17` (tox.ini + workflow). Expected second command: `python 3.12.14` in bandit/checkov/ansible-lint and `aquasecurity/trivy v0.74.0` three times in trivy.yml; `astral-sh/uv` no longer appears (expression value).

- [ ] **Step 7: Note the deliberate gap**

Nothing to edit. `shellcheck.yml` stays manual: the tarball is verified with `SHELLCHECK_SHA256`, which Renovate cannot update. This is recorded in the spec (Task 12).

- [ ] **Step 8: Commit**

```bash
git add .github/workflows/val-unit-tests.yml .github/workflows/bandit.yml .github/workflows/checkov.yml .github/workflows/ansible-lint.yml
git commit -s -m "ci: move tool versions to annotated env vars for Renovate

uv/tox/tox-uv in val-unit-tests now have one source each; bandit, checkov
and ansible-lint pins get '# renovate:' comments.

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 9: Runner and validator workflows

**Files:**
- Create: `.github/workflows/renovate.yml`
- Create: `.github/workflows/renovate-validate.yml`

**Interfaces:**
- Consumes: repository secrets `RENOVATE_APP_ID`, `RENOVATE_APP_PRIVATE_KEY` (required), `DOCKERHUB_USERNAME`, `DOCKERHUB_TOKEN` (optional). Created by the user in Task 11.
- Produces: scheduled Renovate run; `workflow_dispatch` inputs `dry_run` (`full|lookup|extract|none`), `log_level` (`info|debug`), `automerge` (bool).

- [ ] **Step 1: Write `.github/workflows/renovate.yml`**

```yaml
---
name: "Sec :: Renovate"

# Self-hosted Renovate: one weekly grouped dependency PR, separate PRs for
# majors, immediate PRs for CVE fixes. Repo config lives in /renovate.json5
# (see docs/superpowers/specs/2026-10-05-renovate-dependency-updates-design.md).
#
# Authentication is a GitHub App token minted per run. GITHUB_TOKEN would not
# do: it cannot modify .github/workflows/* and PRs it opens do not trigger CI.
# App permissions: contents, pull requests, issues, workflows (write);
# vulnerability alerts, metadata (read).
#
# The workflow_dispatch default is a *dry run* (nothing is written). Pick
# dry_run=none for a real run. Automerge is off unless the input says otherwise.
#
# `schedule` only fires on the default branch. renovate.json5 narrows the
# window further ("before 6am on monday"), so a manual run on another day only
# touches security PRs, which are allowed "at any time".

on:
  schedule:
    - cron: '0 3 * * 1'
  workflow_dispatch:
    inputs:
      dry_run:
        description: "Dry run mode (none = real run that creates branches/PRs)"
        type: choice
        options: [full, lookup, extract, none]
        default: full
      log_level:
        description: "Renovate log level"
        type: choice
        options: [info, debug]
        default: info
      automerge:
        description: "Allow Renovate to automerge PRs that pass all checks"
        type: boolean
        default: false

permissions:
  contents: read

concurrency:
  group: renovate
  cancel-in-progress: false

jobs:
  renovate:
    runs-on: ubuntu-24.04
    timeout-minutes: 120
    defaults:
      run:
        shell: bash
    steps:
      - name: Harden the runner (audit all outbound calls)
        uses: step-security/harden-runner@e14015d583714f6e62063499dc959a02595150a1 # v2.21.1
        with:
          # Switch to `block` after the first real run confirms this list.
          egress-policy: audit
          allowed-endpoints: >
            api.github.com:443
            github.com:443
            objects.githubusercontent.com:443
            raw.githubusercontent.com:443
            ghcr.io:443
            pkg-containers.githubusercontent.com:443
            registry-1.docker.io:443
            auth.docker.io:443
            index.docker.io:443
            production.cloudflare.docker.com:443
            public.ecr.aws:443
            quay.io:443
            registry.access.redhat.com:443
            mcr.microsoft.com:443
            pypi.org:443
            files.pythonhosted.org:443
            registry.npmjs.org:443
            proxy.golang.org:443
            sum.golang.org:443
            storage.googleapis.com:443
            charts.apiseven.com:443
            seaweedfs.github.io:443
            deb.debian.org:443
            api.osv.dev:443

      - name: Checkout code
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false

      - name: Mint GitHub App token
        id: app-token
        uses: actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1 # v3.2.0
        with:
          app-id: ${{ secrets.RENOVATE_APP_ID }}
          private-key: ${{ secrets.RENOVATE_APP_PRIVATE_KEY }}
          permission-contents: write
          permission-pull-requests: write
          permission-issues: write
          permission-workflows: write
          permission-vulnerability-alerts: read
          permission-metadata: read

      - name: Resolve bot identity
        # Commits must be authored by the app's bot user so the DCO sign-off
        # (:gitSignOff) carries the right identity.
        id: bot
        env:
          GH_TOKEN: ${{ steps.app-token.outputs.token }}
          APP_SLUG: ${{ steps.app-token.outputs.app-slug }}
        run: |
          set -euo pipefail
          user_id=$(gh api "/users/${APP_SLUG}%5Bbot%5D" --jq .id)
          echo "git_author=${APP_SLUG}[bot] <${user_id}+${APP_SLUG}[bot]@users.noreply.github.com>" >> "$GITHUB_OUTPUT"

      - name: Compose registry credentials
        # Optional read-only Docker Hub token avoids anonymous pull-rate limits
        # during digest lookups across 70+ Dockerfiles.
        id: hostrules
        env:
          DOCKERHUB_USERNAME: ${{ secrets.DOCKERHUB_USERNAME }}
          DOCKERHUB_TOKEN: ${{ secrets.DOCKERHUB_TOKEN }}
        run: |
          set -euo pipefail
          if [[ -n "${DOCKERHUB_USERNAME}" && -n "${DOCKERHUB_TOKEN}" ]]; then
            rules=$(jq -cn --arg u "$DOCKERHUB_USERNAME" --arg p "$DOCKERHUB_TOKEN" \
              '[{matchHost:"docker.io",username:$u,password:$p}]')
          else
            rules='[]'
          fi
          echo "::add-mask::${rules}"
          echo "rules=${rules}" >> "$GITHUB_OUTPUT"

      - name: Run Renovate
        uses: renovatebot/github-action@230ce922b08968d0a4f6f70f295601daff09ef1d # v46.3.7
        with:
          token: ${{ steps.app-token.outputs.token }}
          renovate-image: ghcr.io/renovatebot/renovate
          # Renovate updates this line itself through the '# renovate:' manager.
          # renovate: datasource=docker depName=ghcr.io/renovatebot/renovate versioning=docker
          renovate-version: 44.133.0-full@sha256:f8172bfd142f957ae5dd9cec535d2cceeb784e9fd6c1e708d2f57bbab1de0990
        env:
          LOG_LEVEL: ${{ inputs.log_level || 'info' }}
          RENOVATE_PLATFORM: github
          RENOVATE_REPOSITORIES: ${{ github.repository }}
          RENOVATE_ONBOARDING: "false"
          RENOVATE_REQUIRE_CONFIG: required
          RENOVATE_GIT_AUTHOR: ${{ steps.bot.outputs.git_author }}
          RENOVATE_HOST_RULES: ${{ steps.hostrules.outputs.rules }}
          RENOVATE_AUTOMERGE: ${{ inputs.automerge == true && 'true' || 'false' }}
          # Empty string = real run. Scheduled runs are always real.
          RENOVATE_DRY_RUN: ${{ (github.event_name == 'workflow_dispatch' && inputs.dry_run != 'none') && inputs.dry_run || '' }}
          # Read access to other GitHub repos for release notes and github-* datasources.
          GITHUB_COM_TOKEN: ${{ steps.app-token.outputs.token }}
```

- [ ] **Step 2: Write `.github/workflows/renovate-validate.yml`**

```yaml
---
name: "Sec :: Renovate config"

# Validates renovate.json5 (schema, deprecated options, regex syntax) on every
# change so a broken config is caught in the PR, not on Monday morning.

on:
  pull_request:
    branches:
      - main
      - 'release-[0-9]+\.[0-9]+'
    paths:
      - renovate.json5
      - .github/workflows/renovate.yml
      - .github/workflows/renovate-validate.yml
  push:
    branches:
      - main
    paths:
      - renovate.json5
      - .github/workflows/renovate.yml
      - .github/workflows/renovate-validate.yml
  workflow_dispatch:

permissions:
  contents: read

jobs:
  validate:
    runs-on: ubuntu-24.04
    timeout-minutes: 10
    defaults:
      run:
        shell: bash
    steps:
      - name: Harden the runner (audit all outbound calls)
        uses: step-security/harden-runner@e14015d583714f6e62063499dc959a02595150a1 # v2.21.1
        with:
          egress-policy: block
          allowed-endpoints: >
            ghcr.io:443
            pkg-containers.githubusercontent.com:443

      - name: Checkout code
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false

      - name: Validate renovate.json5
        env:
          # renovate: datasource=docker depName=ghcr.io/renovatebot/renovate versioning=docker
          RENOVATE_IMAGE: ghcr.io/renovatebot/renovate:44.133.0@sha256:05c512c35c764ef6a179e69c3b30567eca254d67f13a0143479fe3c84852c67a
        run: |
          set -euo pipefail
          docker run --rm -v "${PWD}:/repo:ro" -w /repo "${RENOVATE_IMAGE}" \
            renovate-config-validator --strict renovate.json5
```

- [ ] **Step 3: YAML sanity and expression check**

```bash
python3 - <<'EOF'
import yaml
for f in (".github/workflows/renovate.yml", ".github/workflows/renovate-validate.yml"):
    d = yaml.safe_load(open(f)); print("ok", f, list(d["jobs"]))
EOF
grep -n 'uses:' .github/workflows/renovate.yml .github/workflows/renovate-validate.yml | grep -vE '@[0-9a-f]{40} # v' && echo "UNPINNED ACTION" || echo "all actions SHA-pinned"
```

Expected: both files parse; `all actions SHA-pinned`.

- [ ] **Step 4: Extract and assert the self-update annotations**

```bash
.github/scripts/renovate-local.sh extract '.github/workflows/renovate.yml' '.github/workflows/renovate-validate.yml'
jq -r 'select(.msg=="Extracted dependencies") | .packageFiles["custom.regex"][] | .deps[] | "\(.packageFile)\t\(.depName)\t\(.currentValue)\t\(.currentDigest)"' .renovate-local/extract.jsonl
jq -r 'select(.msg=="Extracted dependencies") | .packageFiles["github-actions"][] | .deps[] | select(.depType=="action") | "\(.depName)\t\(.currentValue)\t\(.currentDigest // "-")"' .renovate-local/extract.jsonl | sort -u
```

Expected first command: two rows, `ghcr.io/renovatebot/renovate` with `44.133.0-full` + the full-image digest, and `44.133.0` + the slim digest. Expected second: `renovatebot/github-action v46.3.7 230ce922…`, `actions/create-github-app-token v3.2.0 bcd2ba49…`, plus checkout and harden-runner, each with a digest.

- [ ] **Step 5: Commit**

```bash
git add .github/workflows/renovate.yml .github/workflows/renovate-validate.yml
git commit -s -m "ci(renovate): scheduled self-hosted runner and config validator

Weekly run with a per-run GitHub App token; workflow_dispatch defaults to a
dry run. Validator runs the official image on config changes.

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 10: Whole-repo dry run and onboarding report

**Files:**
- Create: `docs/superpowers/plans/2026-10-05-renovate-dry-run-report.md`

**Interfaces:**
- Consumes: everything above.
- Produces: the report the upstream proposal cites (manager coverage, counts of updates per lane, warnings).

- [ ] **Step 1: Full lookup over the whole repo**

```bash
export GITHUB_COM_TOKEN=$(gh auth token)
time .github/scripts/renovate-local.sh lookup
```

Expected: exit code 0, 20–40 minutes (738 Python deps and 70 image digests). Rate-limit warnings from Docker Hub are acceptable here and are what the optional Docker Hub secret fixes in CI.

- [ ] **Step 2: Build the report**

```bash
L=.renovate-local/lookup.jsonl
{
echo "# Renovate dry-run report ($(date -u +%F), commit $(git rev-parse --short HEAD))"
echo; echo "## Detected dependencies per manager"; echo
echo '| manager | files | deps |'; echo '|---|---|---|'
jq -r 'select(.msg=="Dependency extraction complete") | .stats.managers | to_entries[] | "| \(.key) | \(.value.fileCount) | \(.value.depCount) |"' $L
echo; echo "## Proposed updates per branch"; echo
echo '| branch | updates |'; echo '|---|---|'
jq -r 'select(.msg=="packageFiles with updates") | .config | .. | objects | select(has("branchName")) | .branchName' $L | sort | uniq -c | sort -rn | awk '{print "| " $2 " | " $1 " |"}'
echo; echo "## Update types"; echo
jq -r 'select(.msg=="packageFiles with updates") | .config | .. | objects | select(has("branchName")) | .updateType' $L | sort | uniq -c | sort -rn | sed 's/^/    /'
echo; echo "## Warnings"; echo
jq -r 'select(.level>=40) | .msg + (if .err then " | " + (.err.message // "") else "" end)' $L | sort | uniq -c | sort -rn | sed 's/^/    /'
echo; echo "## Dependencies with lookup warnings"; echo
jq -r 'select(.msg=="packageFiles with updates") | .config | to_entries[] | .key as $m | .value[] | .deps[] | select((.warnings|length)>0) | "- \($m): \(.depName) \(.currentValue // "") — \(.warnings[0].message)"' $L
} > docs/superpowers/plans/2026-10-05-renovate-dry-run-report.md
cat docs/superpowers/plans/2026-10-05-renovate-dry-run-report.md
```

- [ ] **Step 3: Assertions on the report**

```bash
L=.renovate-local/lookup.jsonl
jq -r 'select(.msg=="packageFiles with updates") | .config | .. | objects | select(has("branchName")) | .branchName' $L | sort -u | grep -vE '^renovate/(weekly|spacy|major-)' && echo "UNEXPECTED BRANCH" || echo "branches ok"
jq -r 'select(.msg=="packageFiles with updates") | .config | to_entries[] | .value[] | select(.packageFile==".github/workflows/shellcheck.yml") | .deps[] | select((.updates|length)>0) | .depName' $L | grep -v '^actions/\|^step-security/\|^ubuntu$' && echo "SHELLCHECK VERSION TARGETED" || echo "shellcheck ok"
```

Expected: `branches ok` and `shellcheck ok`. Fix the config and re-run if not.

- [ ] **Step 4: Commit**

```bash
git add docs/superpowers/plans/2026-10-05-renovate-dry-run-report.md
git commit -s -m "docs(renovate): local dry-run report for the POC proposal

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 11: Hand-off instructions for the user (GitHub side)

**Files:**
- Create: `docs/superpowers/plans/2026-10-05-renovate-github-setup.md`

**Interfaces:**
- Consumes: workflow inputs and secret names from Task 9.

- [ ] **Step 1: Write the instructions**

```markdown
# Renovate POC: GitHub-side setup (manual, fork `mramotowski/enterprise-rag`)

Everything below is done by a human; the automation never pushes or changes settings.

## 1. Create the GitHub App (once, on your user account)

GitHub → Settings → Developer settings → GitHub Apps → New GitHub App
- Name: `erag-renovate-poc` (any unique name; the slug becomes the bot login `<slug>[bot]`)
- Homepage URL: `https://github.com/mramotowski/enterprise-rag`
- Webhook: untick "Active"
- Repository permissions:
  - Contents: Read and write
  - Pull requests: Read and write
  - Issues: Read and write
  - Workflows: Read and write
  - Dependabot alerts: Read-only
  - Metadata: Read-only (default)
- Where can this app be installed: Only on this account
- Create. Note the **App ID**. Generate a **private key** (.pem download).

Install the app: App page → Install App → your account → "Only select repositories" → `enterprise-rag`.

## 2. Repository secrets (fork → Settings → Secrets and variables → Actions)

- `RENOVATE_APP_ID` = the App ID
- `RENOVATE_APP_PRIVATE_KEY` = full contents of the .pem file
- Optional: `DOCKERHUB_USERNAME`, `DOCKERHUB_TOKEN` (read-only access token) to avoid Docker Hub rate limits

## 3. Repository settings on the fork

- Settings → General → Features: enable **Issues** (Dependency Dashboard is an issue).
- Settings → Advanced Security (or Code security): **Dependabot alerts** ON, **Dependabot security updates** OFF
  (Renovate reads the alerts; two bots opening PRs for the same CVE would collide).
- Settings → Actions → General: "Allow GitHub Actions to create and approve pull requests" ON.

## 4. Push and merge the POC branch

    cd /home/mramotow/repos/rag-okf-example/enterprise-rag
    git push origin renovate-poc
    gh pr create -R mramotowski/enterprise-rag --base main --head renovate-poc \
      --title "ci: self-hosted Renovate for weekly dependency updates" \
      --body-file docs/superpowers/specs/2026-10-05-renovate-dependency-updates-design.md

Check that "Sec :: Renovate config" passes on the PR, then merge. Renovate reads
its config from the default branch, and `schedule` only fires there.

## 5. First runs

1. Actions → "Sec :: Renovate" → Run workflow → dry_run = `full`, log_level = `debug`. Read the log:
   it lists every detected dependency and every branch it would create.
2. Run again with dry_run = `none`. Expect: a "Dependency Dashboard (Renovate)" issue,
   a PR from branch `renovate/weekly`, zero or more `renovate/major-*` PRs, and
   `security`-labelled PRs if alerts are open.
3. Close the open Dependabot PRs on the fork once the Renovate PRs cover them.

## 6. Egress lockdown (after one clean real run)

In `.github/workflows/renovate.yml` change `egress-policy: audit` to `block`.
Harden-runner's run summary lists any endpoint that was contacted but not in
the allowlist; add those first.
```

- [ ] **Step 2: Commit**

```bash
git add docs/superpowers/plans/2026-10-05-renovate-github-setup.md
git commit -s -m "docs(renovate): GitHub-side setup instructions for the POC

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

---

### Task 12: Spec refresh and knowledge bundle

**Files:**
- Modify: `docs/superpowers/specs/2026-10-05-renovate-dependency-updates-design.md`
- Modify (workspace, outside this repo): `../knowledge/rag/ci/index.md`, create `../knowledge/rag/ci/dependency-updates.md`, append `../knowledge/log.md` via the `okf-update` skill.

**Interfaces:**
- Consumes: facts established while implementing (deb datasource, native github-actions detection, shellcheck gap, local harness).

- [ ] **Step 1: Update the spec**

In section 2.1 table, change the "Scanner tool pins in workflows" row to:

`| Scanner tool pins in workflows: bandit, checkov, ansible-lint via annotated env vars; setup-python python-version and trivy version detected natively | bandit.yml, checkov.yml, ansible-lint.yml, trivy.yml | regex (# renovate: comments) and github-actions (uses-with) |`

In the "Not Renovate's job" paragraph of 2.1, replace the openssl sentence with:

`apt openssl=3.5.7-1~deb13u3 pins in 24 Dockerfiles are tracked by the dockerfile manager's deb datasource against trixie main (point releases); the trixie-security pocket publishes only Packages.xz, which Renovate cannot read, so security-only builds show up at the next point release.`

Add to the same paragraph: `shellcheck.yml stays manual: its download is checksum-verified via SHELLCHECK_SHA256, which Renovate cannot regenerate.`

In section 3.4 add item 4:

`4. **Generic annotation manager.** Any line preceded by # renovate: datasource=… depName=… [versioning=…] [extractVersion=…] [registryUrl=…] in workflows, deployment YAML, shell scripts and Dockerfiles. Used for seaweedfs chart, busybox/redis/registry image tags, pnpm, redis source tag, spaCy model, scanner tool pins, and the Renovate image itself.`

In section 3.5 add: `Local reproduction: .github/scripts/renovate-local.sh validate|extract|lookup|full runs the same Renovate version in --platform=local mode; every config change in the POC was verified this way before being committed.`

In section 5 item 1 replace the first sentence with: `openssl apt pin 3.5.7-1~deb13u3 duplicated in 24 Dockerfiles. Renovate now tracks it against trixie main, but a security-pocket bump still breaks the build until the next point release.`

- [ ] **Step 2: Commit the spec**

```bash
git add docs/superpowers/specs/2026-10-05-renovate-dependency-updates-design.md
git commit -s -m "docs(spec): record deb datasource, native action detection, shellcheck gap

Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>"
```

- [ ] **Step 3: Knowledge bundle via `okf-update`**

Invoke the `okf-update` skill with this brief: "Add concept `knowledge/rag/ci/dependency-updates.md` (type: CI Workflow, status: draft, resource: fork branch renovate-poc) describing: renovate.json5 lanes (weekly/major/security), custom managers (tox.ini, ARG-split python base, '# renovate:' annotations), the runner workflow and its GitHub App permissions, the local harness `.github/scripts/renovate-local.sh` and the jq queries, and gotchas: deb datasource reads Packages.gz only so trixie-security is invisible; dockerfile manager skips `FROM python:${python_image_version}@…` as contains-variable; config:recommended ignores **/tests/** by default; github-actions manager natively detects setup-python/setup-uv/trivy-action `with:` versions and `container:` images; shellcheck pin is checksum-bound and left manual. Link from `knowledge/rag/ci/index.md`. Do not mark any upstream SHA as indexed; this is fork-only work."

- [ ] **Step 4: Verify the bundle**

```bash
python3 /home/mramotow/repos/rag-okf-example/knowledge/scripts/okf_lint.py
```

Expected: no errors for `rag/ci/dependency-updates.md`.

---

## Self-review notes

- Spec coverage: 2 (scope) → Tasks 2, 4, 7, 8; 2.1 added surfaces → Tasks 7, 8; 3.1 runner → Task 9; 3.2 config → Tasks 2, 3; 3.3 lanes → Task 3; 3.4 custom managers → Tasks 5, 6, 7; 3.5 guardrails → Tasks 1, 9, 10; 3.6 failure handling is runtime behaviour, documented in Task 11; 4 POC plan → Tasks 10, 11; 5 hygiene → Task 12 spec update (hygiene PRs are separate work, out of this plan); 6 alternatives → none needed.
- Deferred by spec, not in plan: models.yaml vLLM tags, gmc Makefile tooling, vLLM UBI Dockerfile ARGs, HF revisions, release-branch lane, automerge.
- Names used consistently: `renovate/weekly`, `renovate/major-*`, `renovate/spacy`; secrets `RENOVATE_APP_ID`, `RENOVATE_APP_PRIVATE_KEY`, `DOCKERHUB_USERNAME`, `DOCKERHUB_TOKEN`; env vars `UV_VERSION`, `TOX_VERSION`, `TOX_UV_VERSION`, `BANDIT_VERSION`, `CHECKOV_VERSION`, `ANSIBLE_LINT_VERSION`, `PNPM_VERSION`, `SPACY_PL_MODEL_VERSION`, `RENOVATE_IMAGE`.
