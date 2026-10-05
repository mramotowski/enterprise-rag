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

Repository **variables** (same page, "Variables" tab) control the run mode; no code change needed to flip them:

- `RENOVATE_DRY_RUN` = `full` for now (`full` | `lookup` | `extract` | `none`; unset behaves as `full`)
- `RENOVATE_LOG_LEVEL` = `debug` for the first runs (`info` | `debug`)
- `RENOVATE_AUTOMERGE` = `false` (`true` | `false`)

Checkov rule CKV_GHA_7 forbids `workflow_dispatch` inputs, which is why these are variables.

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

1. With `RENOVATE_DRY_RUN=full` and `RENOVATE_LOG_LEVEL=debug`: Actions → "Sec :: Renovate" → Run workflow.
   Read the log: it lists every detected dependency and every branch it would create. The local dry
   run never reaches the branch worker, so this is the first place file replacement is exercised:
   grep the log for `Error updating branch` and `Digest is not updated` before any real run.
2. Set `RENOVATE_DRY_RUN=none` (and `RENOVATE_LOG_LEVEL=info`), run again. Expect: a "Dependency Dashboard (Renovate)" issue,
   a PR from branch `renovate/weekly`, zero or more `renovate/major-*` PRs, and
   `security`-labelled PRs if alerts are open.
3. Close the open Dependabot PRs on the fork once the Renovate PRs cover them.

## 6. Egress lockdown (after one clean real run)

In `.github/workflows/renovate.yml` change `egress-policy: audit` to `block`.
Harden-runner's run summary lists any endpoint that was contacted but not in
the allowlist; add those first.
