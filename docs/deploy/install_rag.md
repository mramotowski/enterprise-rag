# Deploy the RAG Layer

[← Docs Index](../README.md)

Full deployment workflow: initialization, access, credentials, configuration, teardown.

## What gets installed

One command installs: model servers, vector database, NATS, Enhanced Data Preparation (EDP), system fingerprint, RAG microservices (retriever, reranker, prompt template, guardrails, LLM), Keycloak config, APISIX gateway, optional MCP gateway, UI, optional HPA.

## Prerequisites

Platform (infrastructure + inference) must be installed first: [Platform Quickstart](https://github.com/intel/enterprise-ai-solutions/blob/main/docs/quickstart/quickstart.md). Hardware: [Prerequisites](../quickstart/prerequisites.md).

## Deployment workflow

> [!IMPORTANT]
> Run every command from the **Enterprise AI Solutions** repo root, not from this repository. `init erag` clones this repository into `ext/enterprise.ai-erag` at a pinned revision.

### Step 1 - Initialize

```bash
./es_auto_installer.sh init erag [--env <name>] [--flavour <name>]
```

| Flavour | Use case |
|---|---|
| `chatqna` (default) | Conversational RAG |
| `docsum` | Document summarization |
| `audioqna` | Voice-based QA |
| `translation` | Language translation |
| `pl_chatqna` | Polish-language RAG |

Seeds `env/<name>/config.erag.yaml` from the flavour's defaults. Model catalog (`models-rag.yaml`) is seeded at install time.

### Step 2 - Configure (optional)

Edit `env/<name>/config.erag.yaml`:

| Setting | Options | Default |
|---------|---------|---------|
| `pipeline_type` | `chatqna` \| `docsum` \| `translation` | `chatqna` |
| `pipeline_variant` | `base` \| `query-rewrite` \| `output_guard` \| `retrieve-rerank` \| `upload` | `base` |
| `inference_models` | List: `name` + `role` (`llm` \| `embedding` \| `reranking`) | `llama3-8b-awq`, `nomic-embed`, `bge-reranker` |
| `vector_databases_vector_store` | `redis-cluster` \| `mssql` \| `pgvector` | `redis-cluster` |
| `mcp_enabled` | `true` \| `false` | `false` |
| `hpa_enabled` | `true` \| `false` | `true` |

Gated models: `export HF_TOKEN="hf_..."` (with `secrets_backend: openbao`, write the token to OpenBao instead, and leave `HF_TOKEN` unset: [Operator-supplied secrets](openbao.md#operator-supplied-secrets-eraguser)). Minimum hardware (≤60 cores / 128 GB): [Prerequisites - Deploying on Minimum Hardware](../quickstart/prerequisites.md#deploying-on-minimum-hardware).

### Step 3 - Deploy

```bash
./es_auto_installer.sh install erag [--env <name>]
```

Validates, deploys inference models, installs RAG components in dependency order, waits for readiness, writes credentials to `env/<name>/logs/rag/`. Takes 10-15 minutes.

Flags: `--env <name>`, `--only` (no deps), `--skip <names>`, `-- <ansible-args>`.

## Model serving

Models deploy automatically via `app_inference_models` during `install erag`. No manual `./model-manager` step needed.

Default (ChatQnA): `llama3-8b-awq` (LLM), `nomic-embed` (embedding), `bge-reranker` (reranking), all in `llm-inference` namespace. LLM via AI Gateway; embedding/reranking via KServe service names.

Customize: edit `inference_models` in `env/<name>/config.erag.yaml`. Each model must exist in `env/<name>/models-rag.yaml`.

## Access and credentials

### Access the UI

Gateway binds ports 80/443 on the cluster node via `hostPort`.

**On cluster node:**

```bash
echo "127.0.0.1 solutions.ai grafana.solutions.ai keycloak.solutions.ai s3.solutions.ai seaweedfs.solutions.ai" | sudo tee -a /etc/hosts
```

Base domain from `base_domain_name` in `env/<name>/global_config.yaml` (default: `solutions.ai`). Each subdomain explicit - wildcards unsupported in `/etc/hosts`.

**From another machine:** `ssh -L 443:localhost:443 user@<cluster-ip>`, then add same line to local `/etc/hosts`.

URLs: `https://solutions.ai` (RAG UI), `https://keycloak.solutions.ai`, `https://grafana.solutions.ai`, `https://seaweedfs.solutions.ai`, `https://s3.solutions.ai`.

> [!IMPORTANT]
> With the default self-signed certificates, visit `https://s3.<base_domain_name>` in your browser and accept the warning **before** ingesting documents. Without it, uploads fail in the browser with no error from the cluster.

### Credentials

Where the generated credentials are depends on `secrets_backend` in `env/<name>/global_config.yaml`.

**`secrets_backend: openbao`:** no credential file is written. Read the values from OpenBao with `bao kv get`, as described in [Credentials in OpenBao - First-login credentials](openbao.md#first-login-credentials).

**`secrets_backend: local` (default):** two files in `env/<name>/logs/rag/`, plus Kubernetes Secrets. The UI passwords are one-time passwords: change them at the first login.

| Service | Username | Where the password is |
|---------|----------|----------|
| UI admin / user / maintainer | `erag-admin`, `erag-user`, `erag-maintainer` | `default_credentials.txt` (`KEYCLOAK_ERAG_*_PASSWORD`); Secret `keycloak/erag-credentials` |
| MCP client (with `mcp_enabled`) | mcp-client (`mcp_keycloak_client_id`) | `default_credentials.txt` (`MCP_CLIENT_SECRET`); Secret `keycloak/erag-credentials` |
| Keycloak admin console | admin | `default_credentials.yaml` (`KEYCLOAK_REALM_ADMIN_PASSWORD`), copied from the platform Secret `keycloak/keycloak-admin-secret` |
| Grafana | admin | not written by this layer: platform Secret `monitoring/grafana-admin-credentials` ([platform docs](https://github.com/intel/enterprise-ai-solutions/blob/main/docs/customize/configuration.md#admin-passwords)) |
| Vector store | the `*_USERNAME` line in `default_credentials.yaml` | `default_credentials.yaml` (`REDIS_PASSWORD`, `POSTGRES_PASSWORD` or `MSSQL_PASSWORD`) |
| Chat history Postgres | the `*_USERNAME` line in `default_credentials.yaml` | `default_credentials.yaml` (`CHAT_HISTORY_POSTGRES_PASSWORD`) |
| System Fingerprint Postgres | fingerprint (database `system_fingerprint`) | `default_credentials.yaml` (`FINGERPRINT_POSTGRES_PASSWORD`); Secret `fingerprint/fingerprint-postgresql-secret` |
| EDP Postgres | edp | `default_credentials.yaml` (`EDP_POSTGRESQL_PASSWORD`, `EDP_POSTGRESQL_ADMIN_PASSWORD`) |
| EDP Redis | default | `default_credentials.yaml` (`EDP_REDIS_PASSWORD`) |
| SeaweedFS S3 | (access/secret keys) | `default_credentials.yaml` (`EDP_SEAWEEDFS_ACCESS_KEY`, `EDP_SEAWEEDFS_SECRET_KEY`) |
| SeaweedFS Admin | admin | `default_credentials.yaml` (`SEAWEEDFS_ADMIN_PASSWORD`) |
| NATS | NKey | `nats-auth` secret (auto-mounted) |

Every install re-writes both files from the Kubernetes Secrets, so deleting them after the first login is safe. Do not encrypt them with `ansible-vault`: the next install reads the file as plain YAML and writes it again in plaintext. To keep credentials out of files altogether, use [OpenBao](openbao.md).

## Configure the deployment

Edit `env/<name>/config.erag.yaml` and re-run `./es_auto_installer.sh install erag --env <name>`. Updates only affected components. See: [Pipeline Configuration](pipelines.md), [Advanced Configuration Guide](../customize/configuration.md).

## Data ingestion, UI and telemetry

Use **Data Ingestion** tab in **Admin Panel** (admin only; ChatQnA and AudioQnA only). User guides: [AudioQnA](../Intel_AI_for_Enterprise_RAG_AudioQnA_User_Guide.pdf), [ChatQnA](../Intel_AI_for_Enterprise_RAG_ChatQnA_User_Guide.pdf), [DocSum](../Intel_AI_for_Enterprise_RAG_DocSum_User_Guide.pdf). Telemetry: [Telemetry Guide](../operate/telemetry.md).

## Single sign-on and SharePoint integration

SSO and SharePoint share one Microsoft Entra ID app registration. Configure in `env/<name>/config.erag.yaml`:

```yaml
erag_keycloak_oidc_endpoint: ""       # enables SSO
erag_keycloak_oidc_alias: "enterprise-sso"
erag_keycloak_oidc_client_id: ""
erag_keycloak_oidc_client_secret: ""
erag_keycloak_oidc_tenant_id: ""      # additionally enables SharePoint
```

All empty = disabled. Partial config rejected. Apply: `./es_auto_installer.sh install erag --env <name>`. Full procedure: [Single Sign-On and SharePoint Integration](../customize/sharepoint.md).

With `secrets_backend: openbao`, leave `erag_keycloak_oidc_client_secret` empty and write the client secret to OpenBao `erag/user/keycloak-oidc` and `erag/user/sharepoint` instead: [Operator-supplied secrets](openbao.md#operator-supplied-secrets-eraguser).

## Remove the installation

```bash
./es_auto_installer.sh teardown erag --env <name>
```

Removes components in reverse order; models undeployed automatically. With `secrets_backend: openbao` it also deletes everything under `<cluster_id>/erag/` in OpenBao, including the `erag/user/*` entries you wrote: see [Credentials in OpenBao - Teardown](openbao.md#teardown).

> [!WARNING]
> Teardown is environment-scoped. Tear down with the same `--env` you installed with: running it against another environment silently does nothing to the one you meant. `teardown erag` keeps the cluster, platform, and inference layers; `teardown infrastructure` removes the cluster and everything on it.

## Troubleshooting

| Issue | Resolution |
|-------|------------|
| **Test deployment** | ChatQnA: `cd .../ext/enterprise.ai-erag/deployment && ./scripts/test_connection.sh`. DocSum: `./scripts/test_docsum.sh`. Translation: `./scripts/test_translation.sh`. |
| **Debug tool** | [Debug Tool Guide](../operate/troubleshooting.md) collects diagnostics. |
| **Status check** | `./es_auto_installer.sh status --env <name>` |
| **Pods stuck pending** | `kubectl describe pod <name> -n <namespace>`. Minimum hardware: verify [tuning steps](../quickstart/prerequisites.md#deploying-on-minimum-hardware). |
| **Models not deploying** | Gated models: `export HF_TOKEN="hf_..."` before install (`secrets_backend: openbao`: write `erag/user/hf-token` instead, see [Credentials in OpenBao](openbao.md#operator-supplied-secrets-eraguser)). |
| **Install stops at an OpenBao check** | See [Credentials in OpenBao - Install failures](openbao.md#install-failures-and-their-fixes). |
| **Connection test fails** | Wait for all pods `Running` in pipeline namespace. |
| **Install fails** | Check `env/<name>/logs/install-erag-*.log`, then re-run (idempotent). |

## Related documentation

[Prerequisites](../quickstart/prerequisites.md), [Quickstart](../quickstart/quickstart.md), [Pipeline Configuration](pipelines.md), [Configuration Reference](../customize/configuration.md), [Platform Documentation](https://github.com/intel/enterprise-ai-solutions/blob/main/docs/README.md).
