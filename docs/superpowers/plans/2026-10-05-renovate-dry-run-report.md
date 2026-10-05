# Renovate dry-run report (2026-10-05, commit fc13928)

Local `renovate --platform=local --dry-run=lookup` (Renovate 44.133.0) over the whole repository except `src/gmc`.
The `src/gmc` Go module slice (1 go.mod, 99 deps) extracts fine but its lookups die on `api.github.com/graphql` ECONNRESET behind the corporate proxy; it was not verifiable from this machine and will be covered by the first run on GitHub-hosted runners.

## Detected dependencies per manager

| manager | files | deps |
|---|---|---|
| docker-compose | 13 | 11 |
| dockerfile | 33 | 184 |
| github-actions | 9 | 52 |
| helm-values | 12 | 42 |
| helmv3 | 4 | 5 |
| kubernetes | 16 | 22 |
| npm | 16 | 158 |
| pep621 | 27 | 738 |
| pip_requirements | 6 | 61 |
| regex | 41 | 45 |
| gomod (separate slice, extraction only) | 1 | 99 |

## Post-filter result

- Filtered out 58 disabled update(s). 1009 update(s) remaining.
- Returning 75 branch(es) (72 after pending filter; one is lock file maintenance. After review, `matchPackageNames` was dropped from the lane rules so it joins the weekly group; Renovate still names its branch `renovate/lock-file-maintenance-weekly`, i.e. two PRs on Monday)
- Disabled updates are python/node/go major+minor bumps and first-party images.

## Proposed updates per branch (pre-filter)

| branch | updates |
|---|---|
| renovate/weekly | 719 |
| renovate/pypi-docarray-vulnerability | 43 |
| renovate/pypi-urllib3-vulnerability | 23 |
| renovate/major-pytest-cov-7.x | 23 |
| renovate/major-pytest-asyncio-1.x | 23 |
| renovate/major-pypi-pytest-vulnerability | 23 |
| renovate/major-protobuf-7.x | 20 |
| renovate/major-pypi-setuptools-vulnerability | 15 |
| renovate/major-ubuntu-26.x | 10 |
| renovate/major-postgres-18.x | 8 |
| renovate/pypi-torch-vulnerability | 7 |
| renovate/major-pypi-transformers-vulnerability | 6 |
| renovate/major-major-react-monorepo | 5 |
| renovate/pypi-langchain-vulnerability | 4 |
| renovate/major-pandas-3.x | 4 |
| renovate/major-node-24.x | 4 |
| renovate/pypi-pip-vulnerability | 3 |
| renovate/pypi-langchain-openai-vulnerability | 3 |
| renovate/npm-pnpm-vulnerability | 3 |
| renovate/major-zod-4.x | 3 |
| renovate/major-pypi-cryptography-vulnerability | 3 |
| renovate/major-protobuf-6.x | 3 |
| renovate/major-numpy-2.x | 3 |
| renovate/major-huggingface-hub-2.x | 3 |
| renovate/pypi-uv-vulnerability | 2 |
| renovate/pypi-transformers-vulnerability | 2 |
| renovate/pypi-pyjwt-vulnerability | 2 |
| renovate/pypi-langchain-core-vulnerability | 2 |
| renovate/major-redis-8.x | 2 |
| renovate/major-pypi-datasets-vulnerability | 2 |
| renovate/major-major-eslint-monorepo | 2 |
| renovate/major-huggingface_hub-2.x | 2 |
| renovate/major-filelock-4.x | 2 |
| renovate/spacy | 1 |
| renovate/pypi-tornado-vulnerability | 1 |
| renovate/pypi-sentence-transformers-vulnerability | 1 |
| renovate/pypi-protobuf-vulnerability | 1 |
| renovate/pypi-nltk-vulnerability | 1 |
| renovate/pypi-mcp-vulnerability | 1 |
| renovate/pypi-anyio-vulnerability | 1 |
| renovate/npm-dompurify-vulnerability | 1 |
| renovate/major-vite-tsconfig-paths-6.x | 1 |
| renovate/major-vite-plugin-dts-5.x | 1 |
| renovate/major-vitejs-plugin-react-6.x | 1 |
| renovate/major-vite-8.x | 1 |
| renovate/major-uuid-11.x | 1 |
| renovate/major-typescript-7.x | 1 |
| renovate/major-sentence_transformers-6.x | 1 |
| renovate/major-registry-3.x | 1 |
| renovate/major-regex-2026.x | 1 |
| renovate/major-prometheus-fastapi-instrumentator-8.x | 1 |
| renovate/major-optimum-intel-2.x | 1 |
| renovate/major-openvino_tokenizers-2026.x | 1 |
| renovate/major-openvino-2026.x | 1 |
| renovate/major-opencv-python-5.x | 1 |
| renovate/major-openai-3.x | 1 |
| renovate/major-openai-1.x | 1 |
| renovate/major-npm-pnpm-vulnerability | 1 |
| renovate/major-nncf-3.x | 1 |
| renovate/major-mongo-9.x | 1 |
| renovate/major-mcp-2.x | 1 |
| renovate/major-marshmallow-4.x | 1 |
| renovate/major-marked-18.x | 1 |
| renovate/major-major-tanstack-table-monorepo | 1 |
| renovate/major-major-tailwindcss-monorepo | 1 |
| renovate/major-major-react-spectrum-monorepo | 1 |
| renovate/major-major-github-artifact-actions | 1 |
| renovate/major-kubernetes-36.x | 1 |
| renovate/major-gunicorn-26.x | 1 |
| renovate/major-globals-17.x | 1 |
| renovate/major-eslint-plugin-simple-import-sort-14.x | 1 |
| renovate/major-eslint-config-prettier-10.x | 1 |
| renovate/major-certifi-2024.x | 1 |
| renovate/major-beanie-2.x | 1 |

## Update types

        581 minor
        199 major
        126 patch
         55 pinDigest
         34 pin
         25 digest

## Lanes

- Weekly lane: `renovate/weekly` (719 pre-filter updates in one PR; after the review fix pass the regex-pin `pinDigest` entries are gone; lock file maintenance is a second Monday PR).
- Major lane: 54 branches `renovate/major-*`.
- Security lane (OSV, no GitHub alerts available locally): 24 branches `renovate/<ds>-<pkg>-vulnerability`.
- spaCy pair: `renovate/spacy` carries spacy ==3.8.11 -> ==3.8.16 (patch); the Polish model stays at 3.8.0 (newest release), same branch when it moves.

## Observations

- 54 major branches on the first run. `prConcurrentLimit: 10` caps open PRs, the rest queue in the Dependency Dashboard. If that is too noisy, set `dependencyDashboardApproval: true` on the major rule so majors are created only when ticked in the dashboard.
- Grouped majors from `group:recommended` monorepo presets get a double prefix (`renovate/major-major-react-monorepo`). Cosmetic.
- Security branches come from OSV here; on GitHub the Dependabot alerts feed adds to them.

## Warnings

    (none besides the local NODE_TLS_REJECT_UNAUTHORIZED notice)

## Dependencies with lookup warnings

- none

## Spot checks

- python base image (24 Dockerfiles): 24x digest -> sha256:6f31d6e9ba2b0a787a3f81c37b004155b87b9efa1b771182bd550c1615745be5;24x minor -> sha256:c3e521df8b2b498a7a682e7e18676771cb80c6b75b8699af886b2d554ce40151;
- openssl apt pin: 24x registry=https://deb.debian.org/debian?suite=trixie&components=main&binaryArch=amd64 updates=0
- setup-uv version expression: skipReason=invalid-value
- shellcheck.yml: no tool-version update proposed (checksum-bound download left manual).
