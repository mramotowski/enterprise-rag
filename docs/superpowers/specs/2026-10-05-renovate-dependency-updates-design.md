# Automated dependency updates with self-hosted Renovate

Date: 2026-10-05
Status: draft, POC on fork `mramotowski/enterprise-rag`, target `intel/enterprise-rag`

## 1. Problem

enterprise-rag has no single owner for dependency freshness:

- Dependabot *security updates* are enabled as a repo setting (there is no
  `.github/dependabot.yml`). They cover pip and npm only, one PR per package per
  directory. Eleven such PRs are open today. GitHub Actions, Dockerfiles, Go, Helm
  and tool versions embedded in workflows are not covered.
- PR intel/enterprise-rag#27 ("Sec :: Dep updater") runs `uv lock --upgrade` for
  every image listed in `deployment/images.yaml`. It is Python only, manual
  (`workflow_dispatch`), and cannot move direct dependencies because ~500 of
  ~700 `pyproject.toml` specifiers are exact `==` pins. Its test run (#28) was a
  single +5332/-5083 PR.
- Action SHAs, `ARG python_image_digest`, tox/uv versions and Helm image tags are
  bumped by hand, so they drift (several Helm values still use `latest`).

Goal: one scheduled, auditable process that keeps every dependency class current,
pins everything by digest, produces a predictable weekly PR, and surfaces CVE
fixes immediately.

## 2. Scope

Dependency surfaces in the repo and the Renovate manager that owns each:

| Surface | Files | Manager |
|---|---|---|
| Python direct deps + lock | 29 `pyproject.toml`, 27 `uv.lock` | `pep621` (uv lockfile support) |
| Python test requirements | 7 `requirements*.txt` under `src/tests` | `pip_requirements` |
| Node workspace | `src/ui/pnpm-lock.yaml` + 15 `package.json` | `npm` (pnpm) |
| Go module | `src/gmc/go.mod` | `gomod` |
| Container base images, plain `FROM` and `COPY --from` | 73 Dockerfiles | `dockerfile` |
| Container base image split into `ARG python_version` / `python_image_digest` | 24 Dockerfiles | custom regex manager |
| Helm chart image tags | `deployment/components/*/values.yaml` | `helm-values` |
| Inline `image:` in templates and manifests | `deployment/components/*/templates/**`, `deployment/roles/**` | `kubernetes` (scoped by `managerFilePatterns`) |
| External chart dependency | `deployment/components/apisix/Chart.yaml` | `helmv3` |
| GitHub Actions `uses:` | `.github/workflows/*.yml` | `github-actions` |
| Tool versions in workflows and tox | `UV_VERSION`/`TOX_VERSION`/`TOX_UV_VERSION` env vars in `val-unit-tests.yml`, `src/tox.ini` `requires` | custom regex managers (`# renovate:` comments; tox.ini pattern) |

### 2.1 Additional surfaces found by a full-repo sweep

Added to the POC (native manager or a one-line regex rule):

| Surface | Files | Manager |
|---|---|---|
| Compose images (`vllm-cpu-release-repo`, `mongo:8.0.11`, `postgres:16.4`, `redis/redis-stack`, `chrislusf/seaweedfs:4.16`) | 9 `docker-compose.y*ml` under `src/comps/**` and `deployment/components/external-seaweedfs` | `docker-compose` |
| Workflow `container:` image and `setup-uv` `version:` input | `val-unit-tests.yml` | `github-actions` (native `container` and `uses-with` dep types) |
| Scanner tool pins in workflows: `bandit`, `checkov`, `ansible-lint` via annotated env vars; `setup-python` `python-version`, trivy-action `version`, `setup-uv` `version` and `container:` images are detected natively | `bandit.yml`, `checkov.yml`, `ansible-lint.yml`, `trivy.yml`, `val-unit-tests.yml` | regex (`# renovate:` comments) and `github-actions` (`uses-with`, `container` dep types) |
| seaweedfs Helm chart `version: "4.37.0"` + `repo:` | `deployment/components/edp/values.yaml` | regex, datasource `helm`, `registryUrlTemplate` from the `repo:` line |
| Image tags in Ansible defaults (`busybox:1.36`, redis `tag: "8.2.2"`) and scripts (`REDIS_IMAGE=`, `REGISTRY_IMAGE=registry:2`) | `deployment/roles/*/defaults/main.yaml`, `*.sh` | regex, datasource `docker` |
| `corepack prepare pnpm@10.33.4` (x3 UI Dockerfiles) | `src/ui/apps/*/Dockerfile` | regex, datasource `npm`, grouped with `npm` |
| `ARG REDIS_VERSION=8.2.2` (git clone tag), spaCy model `pl_core_news_sm-3.8.0` release URL | `vectorstores/.../redis-svs-vamana/Dockerfile`, `retrievers/.../Dockerfile` | regex, `github-tags` / `github-releases` |

Deferred to phase 2 (needs coordination or a bespoke rule):

- `deployment/models.yaml` vLLM image tags: three versions under `runtimes.vllm.versions` keyed by version string, plus 20 `server_version:` entries and `default_version` that must stay consistent. Bumping the image alone would break the mapping. Needs a decision on the data model first.
- Go tooling in `src/gmc/Makefile` (kustomize, controller-tools, golangci-lint, envtest release branch).
- vLLM CPU UBI Dockerfile ARGs (`NUMACTL_VERSION`, `GPERFTOOLS_VERSION`, `VLLM_VERSION="releases/v0.18.0"` which is a branch, not a tag), `pkgs.k8s.io` kubectl repo minor `v1.34`.
- Hugging Face model `revision="<sha>"` pins in 13 guardrail scanner files. No built-in datasource; the `git-refs` datasource against `huggingface.co/<org>/<model>` is possible but untested.
- Security-only lane on `release-X.Y` branches (`baseBranches` + `matchBaseBranches`).

Partly covered: the apt `openssl=3.5.7-1~deb13u3` pins in 24 Dockerfiles are tracked by the `dockerfile` manager's `deb` datasource against trixie main (point releases). The `trixie-security` pocket publishes only `Packages.xz`, which Renovate cannot read, so security-only builds show up at the next point release.

Not Renovate's job (manual hygiene, see section 5): floating `epel-release-latest-9` RPM and unpinned `curl https://astral.sh/uv/install.sh | sh` in the vLLM UBI Dockerfile, first-party `*-base:latest` build-stage images, `deployment/version.yaml`. `shellcheck.yml` stays manual: its download is checksum-verified via `SHELLCHECK_SHA256`, which Renovate cannot regenerate.

Out of scope: ai-solutions and inference repos (same config applies later), automerge.

## 3. Design

### 3.1 Runner

Renovate runs self-hosted inside this repo:

- `.github/workflows/renovate.yml`, SHA-pinned actions, `step-security/harden-runner`
  with egress allowlist. Triggers: `schedule` (Monday 03:00 UTC) and
  `workflow_dispatch` without inputs (Checkov `CKV_GHA_7` forbids them). Run
  mode comes from repository variables: `RENOVATE_DRY_RUN`
  (`full|lookup|extract|none`, unset = `full`), `RENOVATE_LOG_LEVEL`
  (`info|debug`) and `RENOVATE_AUTOMERGE` (`true|false`). Only `none` writes
  anything, so a fork stays in dry-run mode until an operator flips the variable.
- Action `renovatebot/github-action` pinned by SHA; `renovate-image` is the
  `-full` image pinned by tag and digest, annotated so Renovate updates itself
  through the same workflow.
- Authentication: a GitHub App installed on the repo with permissions
  `contents: write`, `pull_requests: write`, `issues: write`, `workflows: write`.
  Token minted per run with `actions/create-github-app-token`. Reasons:
  `GITHUB_TOKEN` cannot modify `.github/workflows/*`, and PRs it opens do not
  trigger CI, so action bumps would be unverifiable. A PAT is tied to a person
  and does not expire per run.
- Registry auth: read-only Docker Hub token in `hostRules` to avoid anonymous
  pull-rate limits during digest lookups across 73 Dockerfiles.
- `permissions: contents: read` at workflow level; the app token carries write.

Egress allowlist (authoritative copy in the workflow): GitHub (`api.github.com`,
`github.com`, `objects.githubusercontent.com`, `raw.githubusercontent.com`),
GHCR, Docker Hub (`registry-1.docker.io`, `auth.docker.io`, `index.docker.io`,
`hub.docker.com`, `production.cloudflare.docker.com`), `public.ecr.aws`, `quay.io`,
`registry.access.redhat.com`, `mcr.microsoft.com`, PyPI (`pypi.org`,
`files.pythonhosted.org`, `download.pytorch.org`, `www.python.org`),
`registry.npmjs.org`, Go (`proxy.golang.org`, `sum.golang.org`,
`storage.googleapis.com`), Helm repos (`charts.apiseven.com`,
`seaweedfs.github.io`), `deb.debian.org`, `api.osv.dev`. Start in
`egress-policy: audit`, switch to `block` after the first real run confirms it.

### 3.2 Configuration (`renovate.json5` at repo root)

Key settings, with the reason each exists:

- `extends: ["config:best-practices", ":dependencyDashboard", ":gitSignOff", ":semanticCommits", "helpers:pinGitHubActionDigests"]`.
  `config:best-practices` brings `pinDigests`, `configMigration`,
  `minimumReleaseAge` baseline and `abandonmentThreshold`. `:gitSignOff` adds
  the DCO `Signed-off-by` trailer that `CONTRIBUTING.md` requires on every commit.
- `enabledManagers` is an explicit allowlist (`github-actions`, `pep621`,
  `pip_requirements`, `npm`, `gomod`, `dockerfile`, `docker-compose`,
  `helm-values`, `helmv3`, `kubernetes`, `custom.regex`). Nothing runs that was
  not reviewed; new managers are a config change with a diff.
- Base-image policy via update types, not version caps: `python`, `node`,
  `golang` images get `major`/`minor` disabled and `patch` + `digest` enabled.
  `ghcr.io/astral-sh/uv` and the `uv`/`tox`/`tox-uv` tool group move together.
- Renovate updates itself: the Renovate image reference in
  `.github/workflows/renovate.yml` carries a `# renovate:` comment matched by
  the workflow regex manager, so the runner is in the weekly PR too.
- Automerge is a runtime switch, not config: `RENOVATE_AUTOMERGE` env, default
  `false`, fed from the repository variable of the same name. The config carries
  `automergeType: "pr"` and `platformAutomerge: true` so flipping the switch
  later needs no config PR. Branch protection still gates merges.
- `schedule: ["before 6am on monday"]`, `timezone: "UTC"`. One run, one batch.
- `minimumReleaseAge: "3 days"` for all package updates except digests. Fresh
  releases are the main supply-chain attack vector (maintainer account
  takeover). A 3-day cooldown lets malicious releases get yanked first.
  Vulnerability PRs ignore it (see 3.3).
- `pinDigests: true` for `docker`, `github-actions` and the custom python-base
  manager. Satisfies OpenSSF Scorecard Pinned-Dependencies.
- `rangeStrategy: "bump"` for pep621 so `==` pins move and `uv.lock` is
  regenerated in the same commit. `lockFileMaintenance` enabled on the same
  Monday schedule so transitive deps refresh (this replaces #27); it lands as
  a second weekly PR because Renovate keeps lock file maintenance on its own
  branch even when grouped.
- `prConcurrentLimit: 10`, `prHourlyLimit: 0`, `rebaseWhen: "behind-base-branch"`.
- `labels: ["dependencies", "renovate"]`, `commitMessagePrefix` conventional
  (`build(deps):`), semantic commit style matching repo history.
- `osvVulnerabilityAlerts: true`, `vulnerabilityAlerts: { enabled: true, labels: ["security"] }`.
- `ignorePaths`: `**/node_modules/**`, `**/.tox/**`, `**/.venv/**`,
  `src/tests/e2e/**` excluded from `pip_requirements` only if they prove noisy
  (decide after dry run).
- `python` constraint from `requires-python` is respected automatically for
  package resolution; the base-image policy above keeps the image on 3.11 so it
  stays aligned with `requires-python = ">=3.11,<3.12"`.

### 3.3 PR lanes (grouping)

Three lanes via `packageRules`:

1. **Weekly deps PR** (`groupName: "weekly dependencies"`,
   `groupSlug: "weekly"`): every `minor`, `patch`, `pin`, `digest`,
   update across all managers. One branch `renovate/weekly`, one PR, rebased
   weekly. PR body lists every change with release notes links, grouped by
   manager. Lock file maintenance shares the schedule and group but Renovate
   always puts it on its own branch (`renovate/lock-file-maintenance-weekly`),
   so Monday produces two PRs: the dependency batch and the lock refresh.
2. **Major updates**: `matchUpdateTypes: ["major"]`, not grouped, one PR per
   dependency, same schedule. A breaking bump must not block the weekly batch.
   Base images (`python`, `node`, `golang`) are excluded from this lane:
   `major`/`minor` disabled per section 3.2. Python 3.12 in particular requires
   changing `requires-python` in 29 `pyproject.toml` files, a manual,
   coordinated change.
3. **Security PRs**: produced by `vulnerabilityAlerts`/OSV, `schedule: at any time`,
   `minimumReleaseAge: null`, not grouped, label `security`. (Renovate 44 has no
   vulnerability selector for `packageRules`, so no extra priority is set.)

Dependabot: keep *alerts* on (they feed Renovate's `vulnerabilityAlerts`), turn
off *security updates* in repo settings once Renovate is on `main`, close the
open Dependabot PRs. Two bots on the same deps create duplicate PRs.

### 3.4 Custom managers

1. **Python base image (ARG split).** Matches the `ARG python_version`,
   `ARG python_image_version`, `ARG python_image_digest` triple in each
   Dockerfile. `depName: python`, `datasource: docker`, `currentValue` is the
   full tag `${python_version}-slim-trixie` reconstructed via
   `currentValueTemplate`, `currentDigest` from the digest ARG. Renovate
   writes the same new digest into all 24 files in one commit. Variant suffix
   (`-slim-trixie`) stays fixed; only the version and digest move.
2. **Tool versions in workflows.** `val-unit-tests.yml` carries job-level env
   vars `UV_VERSION`, `TOX_VERSION`, `TOX_UV_VERSION`, each preceded by
   `# renovate: datasource=pypi depName=…`; `setup-uv` and the
   `uv tool install` line read them. `src/tox.ini` `requires` has a dedicated
   regex manager with the same dep names, so both files move in one branch
   (they must match or tox self-provisions a second copy; see knowledge
   `rag/ci/unit-tests`).
3. **uv in `COPY --from=ghcr.io/astral-sh/uv:0.8.0`.** Native `dockerfile`
   manager already handles `COPY --from`; it lands in the same weekly PR as
   the `uv` tool pins.
4. **Generic annotation manager.** Any line preceded by
   `# renovate: datasource=… depName=… [versioning=…] [extractVersion=…] [registryUrl=…]`
   in workflows, `deployment/**` YAML, shell scripts and Dockerfiles. The value
   may carry `@sha256:<digest>`. Used for the seaweedfs chart version,
   busybox/redis/registry image tags, pnpm, the redis source tag, the Polish
   spaCy model, scanner tool pins (as env vars) and the Renovate image itself.
   The tox.ini and workflow pins share dep names (`tox`, `tox-uv`, `uv`), so
   they move in one branch without an explicit group.

### 3.5 Guardrails and verification

- `renovate-config-validator --strict` runs in PR CI (`Sec :: Renovate config`)
  on changes to `renovate.json5` or the two Renovate workflows.
- Dependency Dashboard issue: lists detected deps, pending (cooldown), rate
  limited, and errored updates. This answers "is it targeting everything".
- Existing PR gates stay the only merge gate: `Val :: Unit tests`, Trivy,
  Checkov, Bandit, Scorecard. No automerge in the POC. Candidate for later:
  automerge `digest` and `pin` updates on green CI.
- Dry run (`RENOVATE_DRY_RUN=full`) before the first real run; the log is the
  onboarding report for the proposal.
- Local reproduction: `.github/scripts/renovate-local.sh validate|extract|lookup|full`
  runs the same Renovate version in `--platform=local` mode (git-tracked files
  only, no branch processing). Every config change in the POC was verified
  this way before being committed; the ARG-split digest replacement was
  additionally verified by calling Renovate's `doAutoReplace` on a copy of
  `src/edp/Dockerfile`.

### 3.6 Failure handling

- Renovate job failure: GitHub Actions failure notification, nothing is pushed.
  No partial branches because Renovate commits per branch atomically.
- Lock regeneration failure for one service (uv resolver conflict): Renovate
  records an "artifact error" in the PR body for that package and keeps the
  rest of the group. Does not fail the whole weekly PR.
- Registry rate limit or egress block: appears in the job log and dashboard;
  the egress allowlist is widened or `hostRules` credentials added.
- Weekly PR red on CI: fix forward in the PR branch, or `ignoreDeps` the
  offender via a `packageRules` entry and let Renovate rebase.

## 4. POC plan on the fork

1. Create GitHub App on `mramotowski`, install on `enterprise-rag` fork, store
   `RENOVATE_APP_ID` and `RENOVATE_APP_PRIVATE_KEY` as repo secrets. Optional:
   `DOCKERHUB_USERNAME` / `DOCKERHUB_TOKEN` read-only.
2. Branch `renovate-poc`: add `renovate.json5`, `.github/workflows/renovate.yml`,
   annotations in `val-unit-tests.yml` and `src/tox.ini`, validator step.
3. Merge to fork `main` (Renovate needs its config on the default branch and
   `schedule` only fires there).
4. `workflow_dispatch` with `dry_run=full`, `log_level=debug`; grep the log for
   `Error updating branch` / `Digest is not updated` (the local dry run never
   reaches the branch worker); then real run.
5. Demo artefacts: Dependency Dashboard issue, one `renovate/weekly` PR, major
   PRs, any security PR, Scorecard Pinned-Dependencies delta.
6. Upstream proposal: this document, the diff, the dry-run summary, and the
   recommendation to close #27 and disable Dependabot security updates.
7. Record non-obvious findings in the OKF bundle (`okf-update`).

## 5. Hygiene findings to fix outside Renovate

Found during the sweep. Each is a small separate PR; none blocks the POC, and
several are the kind of drift the POC proposal argues against.

1. **openssl apt pin** `3.5.7-1~deb13u3` duplicated in 24 Dockerfiles.
   Renovate now tracks it against trixie main, but a security-pocket bump to
   `~deb13u4` still breaks every image build until the next point release
   folds it into main. Options: drop the version and rely on the digest-pinned
   base plus an unpinned `--only-upgrade`, or move the value to one build arg.
   Decision for upstream.
2. **Floating Helm chart**: `prometheus-adapter` installed with no
   `chart_version` in `deployment/roles/app_hpa/tasks/install.yaml`. Pin it;
   then Renovate can track it.
3. **Dead variable**: `apisix_helm_chart_version: "2.10.0"` in
   `roles/app_apisix/defaults/main.yaml` is unreferenced; the real dependency
   is `2.14.1` in `components/apisix/Chart.yaml`. Delete.
4. **Unpinned installs** in `src/comps/llms/impl/model_server/vllm/docker/cpu_ubi/Dockerfile`:
   `curl https://astral.sh/uv/install.sh | sh` and `epel-release-latest-9.noarch.rpm`.
   Replace with a pinned `COPY --from=ghcr.io/astral-sh/uv:<ver>@sha256:…` like
   the other 24 Dockerfiles, and a versioned EPEL RPM.
5. **Divergent copies of the same dependency**: vLLM CPU image appears as
   `v0.11.2`, `v0.14.0`, `v0.19.1` (compose), `v0.24.0`/`v0.21.0`/`v0.19.1`
   (models.yaml) and `0.22.1` (asr Dockerfile); redis `8.2.2` in five places;
   `mongo:5.0.6` in a test helper vs `mongo:8.0.11` in compose. Renovate will
   bump each copy independently, which is correct, but a single source per
   dependency would make the weekly PR smaller.
6. **Must-match pairs** Renovate cannot enforce: `golang:1.25.12` (Dockerfile)
   vs `go 1.25.12` (go.mod), `pl_core_news_sm-3.8.0` vs `spacy==3.8.11`
   major.minor. Group them in `packageRules` so they land in the same commit
   and reviewers see both.
7. `rag-utils` init-container tag `1.5.0` while `version.yaml` says `3.0.0`.
   Likely stale.

## 6. Alternatives rejected

- **Dependabot with `dependabot.yml` and multi-ecosystem groups.** No custom
  manager, so `ARG`-split base images, tool versions in `run:` lines and tox
  requires stay manual. Helm values coverage is partial. Cooldown exists but no
  dependency dashboard.
- **Extend #27.** Reimplements Renovate in bash with less coverage and no
  release-notes, cooldown or vulnerability awareness.
- **Mend-hosted Renovate app.** Least effort, but a third-party app on the Intel
  org needs approval; the self-hosted workflow is the same config and can move
  to the app later with no changes.
