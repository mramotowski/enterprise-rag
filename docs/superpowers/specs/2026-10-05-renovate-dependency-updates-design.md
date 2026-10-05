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
| Inline `image:` in templates and manifests | `deployment/**/*.yaml` | `kubernetes` (scoped by `fileMatch`) |
| External chart dependency | `deployment/components/apisix/Chart.yaml` | `helmv3` |
| GitHub Actions `uses:` | `.github/workflows/*.yml` | `github-actions` |
| Tool versions in workflows and tox | `setup-uv` `version:`, `uv tool install tox==…`, `src/tox.ini` `requires` | custom regex manager with `# renovate:` comments |

Out of scope for the POC: ai-solutions and inference repos (same config applies
later), automerge, model versions in `deployment/models.yaml`, apt package pins
inside Dockerfiles.

## 3. Design

### 3.1 Runner

Renovate runs self-hosted inside this repo:

- `.github/workflows/renovate.yml`, SHA-pinned actions, `step-security/harden-runner`
  with egress allowlist. Triggers: `schedule` (Monday 03:00 UTC) and
  `workflow_dispatch` with inputs `dryRun` (bool) and `logLevel`.
- Action `renovatebot/github-action` pinned by SHA, Renovate image pinned by
  version and digest (Renovate updates itself through the same workflow).
- Authentication: a GitHub App installed on the repo with permissions
  `contents: write`, `pull_requests: write`, `issues: write`, `workflows: write`.
  Token minted per run with `actions/create-github-app-token`. Reasons:
  `GITHUB_TOKEN` cannot modify `.github/workflows/*`, and PRs it opens do not
  trigger CI, so action bumps would be unverifiable. A PAT is tied to a person
  and does not expire per run.
- Registry auth: read-only Docker Hub token in `hostRules` to avoid anonymous
  pull-rate limits during digest lookups across 73 Dockerfiles.
- `permissions: contents: read` at workflow level; the app token carries write.

Egress allowlist: `api.github.com`, `github.com`, `objects.githubusercontent.com`,
`ghcr.io`, `pkg-containers.githubusercontent.com`, `registry-1.docker.io`,
`auth.docker.io`, `index.docker.io`, `production.cloudflare.docker.com`,
`quay.io`, `registry.access.redhat.com`, `mcr.microsoft.com`, `pypi.org`,
`files.pythonhosted.org`, `registry.npmjs.org`, `proxy.golang.org`,
`sum.golang.org`, `charts.apiseven.com`. Start in `egress-policy: audit`, switch
to `block` after the first real run confirms the list.

### 3.2 Configuration (`renovate.json5` at repo root)

Key settings, with the reason each exists:

- `extends: ["config:best-practices", ":dependencyDashboard", "helpers:pinGitHubActionDigests"]`.
  `config:best-practices` brings `pinDigests`, `configMigration`,
  `minimumReleaseAge` baseline and `abandonmentThreshold`.
- `schedule: ["before 6am on monday"]`, `timezone: "UTC"`. One run, one batch.
- `minimumReleaseAge: "3 days"` for all package updates except digests. Fresh
  releases are the main supply-chain attack vector (maintainer account
  takeover). A 3-day cooldown lets malicious releases get yanked first.
  Vulnerability PRs ignore it (see 3.3).
- `pinDigests: true` for `docker`, `github-actions` and the custom python-base
  manager. Satisfies OpenSSF Scorecard Pinned-Dependencies.
- `rangeStrategy: "bump"` for pep621 so `==` pins move and `uv.lock` is
  regenerated in the same commit. `lockFileMaintenance` enabled, grouped into
  the weekly PR, so transitive deps refresh (this replaces #27).
- `prConcurrentLimit: 10`, `prHourlyLimit: 0`, `rebaseWhen: "behind-base-branch"`.
- `labels: ["dependencies", "renovate"]`, `commitMessagePrefix` conventional
  (`build(deps):`), semantic commit style matching repo history.
- `osvVulnerabilityAlerts: true`, `vulnerabilityAlerts: { enabled: true, labels: ["security"] }`.
- `ignorePaths`: `**/node_modules/**`, `**/.tox/**`, `**/.venv/**`,
  `src/tests/e2e/**` excluded from `pip_requirements` only if they prove noisy
  (decide after dry run).
- `python` constraint from `requires-python` is respected automatically; an
  explicit `allowedVersions: "<3.12"` on the python base image rule keeps the
  base image aligned with `requires-python = ">=3.11,<3.12"`.

### 3.3 PR lanes (grouping)

Three lanes via `packageRules`:

1. **Weekly deps PR** (`groupName: "weekly dependencies"`,
   `groupSlug: "weekly"`): every `minor`, `patch`, `pin`, `digest`,
   `lockFileMaintenance` update across all managers. One branch
   `renovate/weekly`, one PR, rebased weekly. PR body lists every change with
   release notes links, grouped by manager.
2. **Major updates**: `matchUpdateTypes: ["major"]`, not grouped, one PR per
   dependency, same schedule. A breaking bump must not block the weekly batch.
   The Python base image is excluded from this lane: `allowedVersions: "<3.12"`
   blocks 3.12 entirely, because moving it requires changing `requires-python`
   in 29 `pyproject.toml` files, which is a manual, coordinated change.
3. **Security PRs**: produced by `vulnerabilityAlerts`/OSV, `schedule: at any time`,
   `minimumReleaseAge: null`, `prPriority: 10`, not grouped, label `security`.

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
2. **Tool versions in workflows.** Lines annotated
   `# renovate: datasource=pypi depName=tox` (and `tox-uv`, `uv`) above
   `version: "0.8.17"` / `uv tool install tox==4.30.2 --with tox-uv==1.28.0 --with uv==0.8.17`.
   `src/tox.ini` `requires` block gets the same annotations. One rule groups
   `tox`, `tox-uv`, `uv` so they always move together (they must match or tox
   self-provisions a second copy; see knowledge `rag/ci/unit-tests`).
3. **uv in `COPY --from=ghcr.io/astral-sh/uv:0.8.0`.** Native `dockerfile`
   manager already handles `COPY --from`; a rule groups it with the `uv` tool
   rule above so one version is used repo-wide.

### 3.5 Guardrails and verification

- `renovate-config-validator` runs in PR CI on changes to `renovate.json5`,
  `.github/workflows/renovate.yml`, and in the Renovate job itself before the run.
- Dependency Dashboard issue: lists detected deps, pending (cooldown), rate
  limited, and errored updates. This answers "is it targeting everything".
- Existing PR gates stay the only merge gate: `Val :: Unit tests`, Trivy,
  Checkov, Bandit, Scorecard. No automerge in the POC. Candidate for later:
  automerge `digest` and `pin` updates on green CI.
- Dry run (`RENOVATE_DRY_RUN=full`) before the first real run; the log is the
  onboarding report for the proposal.

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
4. `workflow_dispatch` with `dryRun=full`, review log; then real run.
5. Demo artefacts: Dependency Dashboard issue, one `renovate/weekly` PR, major
   PRs, any security PR, Scorecard Pinned-Dependencies delta.
6. Upstream proposal: this document, the diff, the dry-run summary, and the
   recommendation to close #27 and disable Dependabot security updates.
7. Record non-obvious findings in the OKF bundle (`okf-update`).

## 5. Alternatives rejected

- **Dependabot with `dependabot.yml` and multi-ecosystem groups.** No custom
  manager, so `ARG`-split base images, tool versions in `run:` lines and tox
  requires stay manual. Helm values coverage is partial. Cooldown exists but no
  dependency dashboard.
- **Extend #27.** Reimplements Renovate in bash with less coverage and no
  release-notes, cooldown or vulnerability awareness.
- **Mend-hosted Renovate app.** Least effort, but a third-party app on the Intel
  org needs approval; the self-hosted workflow is the same config and can move
  to the app later with no changes.
