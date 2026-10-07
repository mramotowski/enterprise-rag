# Credentials in OpenBao

[← Docs Index](../README.md)

With `secrets_backend: openbao` the RAG layer keeps every credential it generates or
consumes in [OpenBao](https://openbao.org), not in files under `env/<name>/logs/rag/`.
External Secrets Operator (ESO) copies them into the Kubernetes Secrets the components
already read, with the same names and keys. The installer never reads a credential value
on the installer host. The default, `secrets_backend: local`, works as before: see
[Install - Credentials](install_rag.md#credentials).

The platform layer installs and runs OpenBao and ESO. Its runbook covers the
operations that are not specific to RAG: init and unseal, upgrades, external
OpenBao, the route, and generate-root. It is the
[OpenBao secrets backend runbook](https://github.com/intel/enterprise-ai-solutions/blob/main/docs/deploy/openbao.md)
in Intel® AI for Enterprise Solutions, called "the platform runbook" below.

All commands run from the Intel® AI for Enterprise Solutions repo root. The examples use
the defaults: KV mount `intel-ai` (`openbao_kv_mount`) and worker namespace `erag-secrets`
(`erag_secrets_namespace`). `<cluster_id>` is `openbao_cluster_id`, which defaults to the
env name.

- [Enable it](#enable-it)
- [Path layout](#path-layout)
- [Log in to OpenBao](#log-in-to-openbao)
- [First-login credentials](#first-login-credentials)
- [Operator-supplied secrets (erag/user/\*)](#operator-supplied-secrets-eraguser)
- [Install failures and their fixes](#install-failures-and-their-fixes)
- [In-cluster Jobs and their images](#in-cluster-jobs-and-their-images)
- [Migrate an existing deployment](#migrate-an-existing-deployment)
- [How a change in OpenBao reaches the services](#how-a-change-in-openbao-reaches-the-services)
- [Rotate a credential](#rotate-a-credential)
- [Teardown](#teardown)
- [Backup and restore](#backup-and-restore)
- [External OpenBao, route and CA bundle](#external-openbao-route-and-ca-bundle)
- [Known limitations](#known-limitations)

## Enable it

Prerequisites:

- `secrets_backend` is one key for the whole env, in `env/<name>/global_config.yaml`. It
  applies to every layer of the env.
- The platform layer is installed with it. In internal mode (the default) the platform
  install runs OpenBao and asks you to save the unseal shares. In external mode you
  prepare your OpenBao first. See the platform runbook,
  [First install](https://github.com/intel/enterprise-ai-solutions/blob/main/docs/deploy/openbao.md#first-install-init-unseal-bootstrap)
  and [External OpenBao](https://github.com/intel/enterprise-ai-solutions/blob/main/docs/deploy/openbao.md#external-openbao).
- OpenBao is unsealed, and the `ClusterSecretStore` `openbao-erag` is `Ready`.
- `erag` is in `openbao_layers` (the default `[erag]`).
- The images of the [in-cluster Jobs](#in-cluster-jobs-and-their-images) can be pulled.

Steps:

1. Set the backend in `env/<name>/global_config.yaml` and install the platform:

   ```yaml
   secrets_backend: openbao
   openbao_mode: internal          # or external, with openbao_address, openbao_ca_file, openbao_cluster_id
   ```

   ```bash
   ./es_auto_installer.sh install platform --env <name>
   ```

2. Write the [operator-supplied secrets](#operator-supplied-secrets-eraguser) your
   configuration needs (HF token, S3 keys, SharePoint, SSO, LDAP) to OpenBao. Remove
   them from `config.erag.yaml` and unset `HF_TOKEN`, `s3_access_key` and `s3_secret_key`.
3. Install the layer as usual:

   ```bash
   ./es_auto_installer.sh install erag --env <name>
   ```

4. Read the [first-login credentials](#first-login-credentials) from OpenBao.

What the install does with the backend on:

- Before it generates or projects anything, it probes OpenBao from a Job in namespace `erag-secrets`. If
  OpenBao is unreachable, uninitialized or sealed, or the worker cannot log in, the
  install stops before it changes anything. It never falls back to local files.
- Before each component, a worker Job (ServiceAccount `erag-secrets-worker`, OpenBao
  role `erag-secrets-worker`) creates the missing entries with generated values. It
  never overwrites an existing entry, so a re-run keeps every value.
- For each Secret, the install creates an `ExternalSecret` on store `openbao-erag` that
  ESO turns into the Secret (`creationPolicy: Owner`). It labels each namespace
  `secrets.ai-solutions/erag: "true"` and annotates it with the paths it may read.
- ESO re-reads OpenBao every `eso_refresh_interval` (default `1h`). If OpenBao is down,
  running pods keep their Secrets; only the refresh stops.
- Nothing is written to `default_credentials.yaml`, `default_credentials.txt`, Helm
  values or Helm release storage. With the backend on, `secure_logs` is on too, so the
  installer log masks secret values.

## Path layout

Every RAG entry is under `<openbao_kv_mount>/<cluster_id>/erag/<component>/<credential>`
in a KV v2 mount. An entry holds secret material only. Usernames and client IDs are
fixed or come from configuration (`mcp_keycloak_client_id`, ...), and the projected
Secrets carry them as before.

| Path under `<cluster_id>/` | Keys | Projected into (namespace / Secret) |
|---|---|---|
| `erag/keycloak/erag-admin` | `password` | keycloak / `erag-credentials` |
| `erag/keycloak/erag-user` | `password` | keycloak / `erag-credentials` |
| `erag/keycloak/erag-maintainer` | `password` | keycloak / `erag-credentials` |
| `erag/keycloak/mcp-client` | `client_secret` | keycloak / `erag-credentials` (with `mcp_enabled`) |
| `erag/keycloak/grafana-oauth` | `client_secret` | monitoring / `grafana-sso-env`; keycloak / `keycloak-configurator-sensitive` |
| `erag/keycloak/edp-oidc` | `client_secret` | edp / `keycloak-minio-secret`, `edp-access-secret`; keycloak / `keycloak-configurator-sensitive` |
| `erag/nats/auth` | `seed`, `public_key` | nats / `nats-auth`; `system` and the pipeline namespace / `nats-auth` |
| `erag/vector-db/redis`, `.../pgvector`, `.../mssql` | `password` | vdb / `<engine>-secret`; pipeline and edp / `vector-database-config` |
| `erag/chat-history/postgres` | `password` | chat-history / `mongo-database-secret` |
| `erag/fingerprint/postgres` | `password` | fingerprint and `system` / `fingerprint-postgresql-secret` |
| `erag/edp/postgresql` | `password`, `admin_password` | edp / `edp-postgresql-secret` |
| `erag/edp/redis` | `password` | edp / `edp-redis-secret`, `edp-celery-secrets` |
| `erag/edp/object-store` | `access_key`, `secret_key` | edp / `edp-access-secret`; seaweedfs / `seaweedfs-s3-secret` |
| `erag/seaweedfs/admin` | `password` | seaweedfs / `seaweedfs-admin-secret` |
| `erag/user/*` | written by you | see [Operator-supplied secrets](#operator-supplied-secrets-eraguser) |

The source of this table is the credential registry,
[`deployment/roles/app_secrets/files/registry.yaml`](../../deployment/roles/app_secrets/files/registry.yaml).

Two values stay outside OpenBao by design. The SeaweedFS STS signing key is ephemeral:
it is regenerated on every run and never stored. The MCP CA copy is a public
certificate. The platform's own credentials (the Keycloak admin, Grafana admin, the
shared PostgreSQL owners) stay in platform Kubernetes Secrets.

## Log in to OpenBao

Every client authenticates with OpenBao's Kubernetes auth (`auth/<openbao_auth_mount>`),
using a short-lived ServiceAccount token. There are no static tokens:

| OpenBao role | Who | Rights on `<cluster_id>/erag/` |
|---|---|---|
| `eso-erag` | ESO (`external-secrets/external-secrets`), store `openbao-erag` | read |
| `erag-secrets-worker` | worker and rotator Jobs (`erag-secrets/erag-secrets-worker`) | read, write, delete |
| `erag-secrets-importer` | importer Job (`erag-secrets/erag-secrets-importer`) | read, create, update |
| `operator` | people (`openbao/openbao-operator`) | read, create, update, list |

People use the shared `operator` role. It can read, create and update every path of the
cluster, but it cannot delete. Log in as described in the platform runbook,
[Operator login](https://github.com/intel/enterprise-ai-solutions/blob/main/docs/deploy/openbao.md#operator-login).
In internal mode you work in a shell inside `openbao-0`. With the route or external mode
you can also use a `bao` CLI on your workstation. Every `bao` command below runs in that
logged-in shell. Revoke the token when you are done (`bao token revoke -self`).

`bao kv get -field=<key>` prints the value on your terminal only. To pass a value in
without putting it in your shell history or a process list, use `<key>=-`: `bao` then
reads it from stdin. `bao` stores stdin as it is, including a trailing newline, so do not
type the value and press Enter. Read it into a variable first and pipe it without a
newline:

```bash
printf 'value: '; read -rs V; echo        # paste the value, press Enter (not echoed)
printf '%s' "$V" | bao kv put -mount=intel-ai <cluster_id>/erag/user/hf-token token=-
unset V
```

The commands below write `<key>=-` for short; feed each one this way.

## First-login credentials

The RAG UI users are created with these passwords and must change them at first login.
The usernames are `erag-admin`, `erag-user` and `erag-maintainer`:

```bash
bao kv get -mount=intel-ai -field=password <cluster_id>/erag/keycloak/erag-admin
bao kv get -mount=intel-ai -field=password <cluster_id>/erag/keycloak/erag-user
bao kv get -mount=intel-ai -field=password <cluster_id>/erag/keycloak/erag-maintainer
```

After the first login the value in OpenBao is only the initial password. The configurator
creates users but never updates them: a user that already exists in the realm keeps its
password, even when OpenBao holds another one.

The MCP client (with `mcp_enabled`) has client ID `mcp_keycloak_client_id` (default
`mcp-client`):

```bash
bao kv get -mount=intel-ai -field=client_secret <cluster_id>/erag/keycloak/mcp-client
```

The Keycloak admin console user (`admin`) and the Grafana `admin` belong to the platform.
erag never stores them, in either mode. Read them from the platform Secrets, as described
in the platform
[configuration reference](https://github.com/intel/enterprise-ai-solutions/blob/main/docs/customize/configuration.md#admin-passwords):

```bash
kubectl get secret -n keycloak keycloak-admin-secret -o jsonpath='{.data.password}' | base64 -d; echo
kubectl get secret -n monitoring grafana-admin-credentials -o jsonpath='{.data.password}' | base64 -d; echo
```

The service credentials (vector store, EDP, SeaweedFS) are under the paths in
[Path layout](#path-layout), for example
`bao kv get -mount=intel-ai <cluster_id>/erag/seaweedfs/admin` (user `admin`).

There is no credential file to protect or delete in this mode.

## Operator-supplied secrets (erag/user/\*)

You write these entries; the installer only reads them. With the backend on, each one is
read **only** from OpenBao:

| Path under `<cluster_id>/` | Keys | Needed when | Replaces (local mode) |
|---|---|---|---|
| `erag/user/hf-token` | `token` | gated models; optional otherwise | `HF_TOKEN`, `hugging_token` |
| `erag/user/edp-s3` | `access_key_id`, `secret_access_key` | `edp_storage_type: s3` or `s3compatible` (ONTAP S3 included) | `edp_s3_access_key_id`, `edp_s3_secret_access_key`, `edp_s3_compatible_access_key_id`, `edp_s3_compatible_secret_access_key`, `s3_access_key`, `s3_secret_key` |
| `erag/user/sharepoint` | `client_secret` | `erag_keycloak_oidc_tenant_id` is set (SharePoint) | `erag_keycloak_oidc_client_secret` |
| `erag/user/keycloak-oidc` | `client_secret` | `erag_keycloak_oidc_endpoint` is set (SSO) | `erag_keycloak_oidc_client_secret` |
| `erag/user/ldap-bind` | `password` | `erag_keycloak_federation_endpoint` is set (LDAP) | `erag_keycloak_federation_bind_password` |

Write an entry before the install that needs it, feeding each value as shown in
[Log in to OpenBao](#log-in-to-openbao). `kv put` creates the entry, and `kv patch` adds a
second key to it (`bao` may suggest adding the `patch` capability; the write succeeds
without it):

```bash
bao kv put   -mount=intel-ai <cluster_id>/erag/user/hf-token token=-
bao kv put   -mount=intel-ai <cluster_id>/erag/user/edp-s3 access_key_id=-
bao kv patch -mount=intel-ai <cluster_id>/erag/user/edp-s3 secret_access_key=-
```

The non-secret settings stay in `config.erag.yaml`: `edp_storage_type`, the S3 endpoint
and region, `erag_keycloak_oidc_endpoint`, `erag_keycloak_oidc_client_id`,
`erag_keycloak_oidc_tenant_id`, the LDAP endpoint and bind DN.

**Preflight.** When a config key or environment variable from the last column is still
set, the install fails before it changes anything. The message names the variable, the
OpenBao path and the key, never the value:

```
CONFIGURATION FAILED
1 issue(s) must be resolved before continuing:
1. The environment variable HF_TOKEN is set, but with secrets_backend: openbao it is read
   only from OpenBao intel-ai/<cluster_id>/erag/user/hf-token key token. Unset HF_TOKEN
   before the install and write the value there: bao kv patch ...
```

Remove the key from `config.erag.yaml` (or unset the variable), write it to OpenBao,
and re-run.

**HF token.** It is optional, as in local mode. When `erag/user/hf-token` exists, it is
projected into the pipeline namespace (`hf-token-secret`), audio
(`audio-hf-token-secret`), the model namespace (`llm-inference` / `hf-token`, key
`token`) and `erag-secrets` / `hf-token` (the vector-dims Job). There `model-manager`
reads it, with `MM_HF_TOKEN_FROM_SECRET=true`. This needs an Intel® AI for Enterprise
Inference release whose `model-manager` supports that variable. Without the entry the
install warns "no HF token", and gated models fail to download.

**S3 and ONTAP S3.** Write `erag/user/edp-s3` for both `s3` and `s3compatible`. In
local mode ONTAP S3 derives `s3compatible` from the config access key. With the backend
on, that key is no longer in the config, so set `edp_storage_type: s3compatible`
explicitly. See [Object Store](../customize/object_store.md).

**SharePoint and SSO with one Entra app.** In local mode, one
`erag_keycloak_oidc_client_secret` serves both. With the backend on, write the same
client secret to both `erag/user/sharepoint` and `erag/user/keycloak-oidc`. See
[SharePoint](../customize/sharepoint.md).

**Changing a value.** `bao kv put` (or `patch`) writes a new version. For `edp-s3`,
`sharepoint` and `hf-token`, then run a [rotation](#rotate-a-credential) to sync and
restart the consumers. For `keycloak-oidc` and `ldap-bind`, run a normal
`install erag`: the Keycloak configurator applies them.

## Install failures and their fixes

| Message | Cause | Fix |
|---|---|---|
| `OpenBao at ... is sealed` | a pod restarted | unseal ([platform runbook](https://github.com/intel/enterprise-ai-solutions/blob/main/docs/deploy/openbao.md#unseal-after-a-restart)), re-run |
| `OpenBao at ... is unreachable from namespace erag-secrets` | OpenBao down, every pod sealed, NetworkPolicy, wrong CA | check `kubectl -n openbao get pods`, then the platform install |
| `the worker could not log in to OpenBao as role erag-secrets-worker` | role binding, audience, or TokenReview from OpenBao | the role must bind `erag-secrets-worker` in `erag-secrets` with audience `openbao_auth_audience` |
| `<id> (...erag/user/...): missing - operator-supplied: write ... first` | a feature needs an entry that is not there | write it ([above](#operator-supplied-secrets-eraguser)), re-run |
| `<id> (...): incomplete - ... lacks key(s) <key>` | the entry exists, but a key is missing (for example an `edp-s3` entry with one key, or a key added in a newer release) | `bao kv patch -mount=intel-ai <cluster_id>/<path> <key>=-`, re-run |
| `<id> (...): deleted - ... restore it (bao kv undelete) or remove its metadata` | the current version was deleted | `bao kv undelete -mount=intel-ai -versions=<n> <cluster_id>/<path>`, or remove the entry (needs a token that may delete, see below) to have it generated again |
| `app_edp: edp_rbac_enabled ... is not supported yet when Secrets are projected from OpenBao` | SeaweedFS IAM with Keycloak STS needs a local signing key setup | set `edp_rbac_enabled: false`, or use the local backend |

The `operator` role cannot delete. To remove an entry
(`bao kv metadata delete -mount=intel-ai <cluster_id>/<path>`), use a temporary root
token ([platform runbook, generate-root](https://github.com/intel/enterprise-ai-solutions/blob/main/docs/deploy/openbao.md#change-the-bootstrap-generate-root)).
A removed generated entry gets a new value at the next install, and the service that
already holds the old value then no longer matches it.

**The charts' `externalSecrets` value.** The EDP, vector database and audio charts have a
value `externalSecrets`. The roles set it to `true` when Secrets are projected. Then the
charts template no Secret, and ESO owns them. Never set it yourself or override it in a
manual `helm upgrade`: with `externalSecrets: false` Helm templates the Secrets again,
and two owners fight over them.

When an `ExternalSecret` does not sync (`SecretSyncedError`), the Secret keeps its last
value. `kubectl -n <namespace> describe externalsecret <name>` shows why. The admission
policy for ExternalSecret paths is described in the platform runbook,
[External Secrets Operator](https://github.com/intel/enterprise-ai-solutions/blob/main/docs/deploy/openbao.md#external-secrets-operator).

## In-cluster Jobs and their images

With the backend on, everything that touches a credential value runs in a Job, not on
the installer host: in `erag-secrets` (`erag_secrets_namespace`), except the MCP edge
check and the Keycloak client drift check, which run next to the Secrets they read
(keycloak namespace). Their images are
pulled from public registries by default. For a production or restricted cluster,
mirror them and pin them by digest in `env/<name>/config.erag.yaml`:

| Job | What it does | Image setting (default) |
|---|---|---|
| worker (`erag-secrets-worker`) | probe, ensure, status, delete | `app_secrets_worker_image` (`quay.io/openbao/openbao:2.7.0`) |
| importer (`erag-secrets-importer`) | [migration](#migrate-an-existing-deployment) | `app_secrets_importer_image` (= `vector_dims_job_image`) |
| rotator | [rotation](#rotate-a-credential) | `app_secrets_rotator_image` (= `app_secrets_importer_image`) |
| vector-dims (`erag-vector-dims-<hash>`) | looks up the embedding size of `embedding_model_id` with the projected HF token | `vector_dims_job_image` (`docker.io/library/python:3.12-slim`) |
| MCP edge check (keycloak namespace) | gets an agent token through the gateway and checks that the MCP route accepts it (status codes only); needs to reach the Envoy gateway Service | `mcp_edge_auth_job_image` (= `vector_dims_job_image`) |
| Keycloak client drift check (keycloak namespace, `validate erag` only) | compares each erag Keycloak client secret with the OpenBao value through the Keycloak admin API (match/drift only) | `keycloak_drift_job_image` (= `vector_dims_job_image`) |

```yaml
# env/<name>/config.erag.yaml
app_secrets_worker_image: "registry.example.com/openbao/openbao@sha256:<digest>"
vector_dims_job_image: "registry.example.com/library/python@sha256:<digest>"
```

The worker needs the `bao` CLI and busybox, which the OpenBao server image has. The
others need only Python 3 and its standard library.

**The vector-dims Job.** It runs only when `vector_databases_vector_dims` is not set.
Its log holds only the JSON result line, never the token. When it fails, the install
names the Job. Then:

```bash
kubectl -n erag-secrets describe job erag-vector-dims-<hash>
kubectl -n erag-secrets logs job/erag-vector-dims-<hash>
```

Or set `vector_databases_vector_dims` in `config.erag.yaml` to skip the lookup. The Job
needs egress to `huggingface.co`, and through your proxy when `http(s)_proxy` is set.

## Migrate an existing deployment

An env installed with `secrets_backend: local` can switch to OpenBao. Every service and
login keeps its current password.

> [!WARNING]
> The migration is one way. Once it is finalized, no local files, markup or Helm history
> remain to go back to. Switching an env back to `secrets_backend: local` is not
> supported: it would generate new passwords against existing databases. The install
> refuses it while erag ExternalSecrets or namespaces with the `secrets.ai-solutions/erag`
> label exist. Tear erag down first (with `secrets_backend: openbao`), or override with
> `-e erag_secrets_switch_to_local_confirmed=true` if you will re-enter every credential.

Before you start:

1. Take a [backup](../operate/backup.md), if backup is enabled.
2. Install the platform with `secrets_backend: openbao` (see [Enable it](#enable-it)).
3. Write the [operator-supplied secrets](#operator-supplied-secrets-eraguser) that the
   env uses, including the HF token. Remove them from `config.erag.yaml`, and unset
   `HF_TOKEN`, `s3_access_key` and `s3_secret_key`.
4. Archive the env logs you need. Finalize deletes every `*.log` file directly in
   `env/<name>/logs/` that is older than the migration start, of every layer (platform
   and inference too). Logs from before `secure_logs` may hold secrets, so keep the
   copies in a protected place.
5. Change nothing else in the same run. In particular, enable MCP (`mcp_enabled`) or EDP
   (`edp_enabled`) only after the migration. The import fails when it finds no value for
   a client secret that the configuration requires.

Then run `./es_auto_installer.sh install erag --env <name>`. The run:

1. **imports** (before anything is generated): an importer Job reads the running
   Secrets in-cluster and writes each value to OpenBao, never overwriting an entry. It
   then marks the Helm-owned Secrets `helm.sh/resource-policy: keep`, so that Helm keeps
   them and ESO adopts them, and removes the local `meta.erag/*` markup. Its temporary
   ServiceAccount, Roles and RoleBindings are deleted at the end;
2. installs every component with projected Secrets;
3. **finalizes** (after the Helm upgrades): deletes `default_credentials.yaml`,
   `default_credentials.txt` and `env/<name>/logs/tmp/rag/`, and the `*.log` files of
   the runs before the migration in `env/<name>/logs/`. It prunes the history of every
   erag Helm release to its latest revision.

Per credential the import reports `created`, `exists` (OpenBao already holds the same
value) or `absent` (no local value; it is generated later). It fails, before any Secret
is changed, on:

| Result | Meaning | Fix |
|---|---|---|
| `conflict` | OpenBao already holds a different value | if the entry was written by mistake, remove it (`bao kv metadata delete`, root token) and re-run; otherwise find out which value the service really uses |
| `missing` | a required credential (the Keycloak users; the MCP or EDP client secret when enabled) has no local value | restore the local Secret, or migrate with that feature disabled and enable it afterwards |
| `error`: the sources disagree | two local Secrets hold different values for one key | make them agree (the value the service uses), re-run |
| `error`: found only some keys | an entry would get only part of its keys | restore the missing local Secret key, re-run |
| `error`: the current version is deleted | the OpenBao entry was deleted | `bao kv undelete`, or remove the metadata, re-run |

A failed import leaves the local deployment working. Fix the cause and re-run.

**Migration state.** ConfigMap `erag-secrets/erag-secrets-migration` (no secret data)
records the state:

| `state` | Meaning |
|---|---|
| `imported` | local material was found and imported; finalize is still to run, or to finish |
| `native` | the env never had local credentials (a fresh OpenBao install) |
| `done` | finalized: credentials are read from OpenBao only |

Import does nothing when the state is `native` or `done`. Finalize sets `done` only when
every erag release has a deployed revision from after the migration. Otherwise it warns
"Migration not finalized yet" and names the releases whose current revision still holds
local values. Upgrade them (install the layer again) or uninstall them; the next run
finishes. To have the next run decide again, delete the ConfigMap. Do that only when
the state is wrong, for example `native` on an env that still has local Secrets.

```bash
kubectl -n erag-secrets get configmap erag-secrets-migration -o jsonpath='{.data.state}'; echo
kubectl -n erag-secrets delete configmap erag-secrets-migration
```

Also note:

- Finalize prunes only Helm's default Secret storage driver. With
  `HELM_DRIVER=configmap` or `sql`, delete the old revisions yourself.
- A Helm-owned Secret that ESO never adopts keeps its local value after the upgrade
  (`helm.sh/resource-policy: keep`), and it survives teardown. An example is the
  pipeline `hf-token-secret` while `erag/user/hf-token` is not written. Delete such a
  Secret by hand once nothing uses it.
- The importer image needs mirroring and pinning like the others
  ([In-cluster Jobs](#in-cluster-jobs-and-their-images)).
- Finalize needs a deployed revision from after the migration for every erag release. A
  release whose last revision is `failed` (for example a Helm wait that timed out) is not
  deployed again by a reinstall with unchanged chart and values; the warning names it.
  APISIX (`auth-apisix`) redeploys itself in that case. For another release, run
  `helm -n <namespace> rollback <name> <revision>` (the last revision from after the
  migration), then `install erag` again.

## How a change in OpenBao reaches the services

OpenBao is the only source of the erag credentials. A change flows one way, from
OpenBao to the services. Nothing reads a value back from the services or from Keycloak.

| Step | What carries it | When |
|---|---|---|
| OpenBao → Kubernetes Secret | ESO, the `ExternalSecret` of each Secret | at the next refresh (`eso_refresh_interval`, default `1h`), or right away when a rotation force-syncs it |
| Secret → pod | the pod reads it | at the next pod start for environment variables (most erag services) |
| OpenBao → the server that checks it (a database, Redis, Keycloak) | a [rotation](#rotate-a-credential) hook, or the Keycloak configurator at `install erag` | only then |

So:

- **Change a generated credential only by rotating it** (`erag_rotate`). Writing a new
  value with `bao kv put` changes the projected Secret but not the database or Keycloak
  that checks it: after the next refresh and restart the service presents a password the
  server does not know, and fails.
- **Operator-supplied entries (`erag/user/*`) are written by you.** Write the new version,
  then rotate the id (`user/hf-token`, `user/edp-s3`, `user/sharepoint`: syncs and
  restarts at once) or run a normal `install erag` (`user/keycloak-oidc`,
  `user/ldap-bind`: the configurator applies them to Keycloak).
- **Keycloak client secrets** (`mcp-client`, `grafana-oauth`, the EDP OIDC client): rotate
  them with the installer. A secret regenerated in the Keycloak admin console breaks the
  services that use it and is not copied to OpenBao; `validate erag` reports it, and
  `install erag` sets the OpenBao value on Keycloak again. To keep a value set in Keycloak
  instead, write it to OpenBao (`bao kv patch ... client_secret=-`) and run `install erag`.
- **Keycloak user passwords** (`erag-admin`, `erag-user`, `erag-maintainer`) belong to the
  users after their first login. OpenBao keeps only the initial password, and no run
  changes an existing user's password (see [First-login credentials](#first-login-credentials)).
- Some credentials cannot be changed after install yet (NATS, the Redis Cluster vector
  store, MSSQL, the SeaweedFS identities); the table under [Rotate a credential](#rotate-a-credential)
  says why.

## Rotate a credential

Rotation needs the backend on. A rotate-only run changes only the credentials you name:

```bash
./es_auto_installer.sh install erag --env <name> --only -- -e 'erag_rotate=[edp/redis,fingerprint/postgres]'
```

With `erag_rotate` set, the platform and inference layers and every other erag component
are skipped. Keep `--only`: without it, an installer-provisioned cluster still runs the
installer's infrastructure step first.

For each credential, the rotator Job writes a new version to OpenBao and sets it on the
server. If that fails, it restores the previous version. The run then force-syncs the
`ExternalSecret`s and restarts the workloads that read them only at start. If a run stops
in between, its message gives the `bao kv rollback` command that restores the previous
version.

| Credential | Rotation | Restarted |
|---|---|---|
| `keycloak/mcp-client` | new client secret in Keycloak | nothing; agents read the new value from OpenBao |
| `keycloak/grafana-oauth` | new client secret in Keycloak | Grafana |
| `keycloak/edp-oidc` | new client secret in Keycloak | EDP backend, celery, flower |
| `vector-db/pgvector` | `ALTER ROLE` | retriever, EDP |
| `chat-history/postgres` | `ALTER ROLE` | chat-history, FerretDB |
| `fingerprint/postgres` | `ALTER ROLE` | fingerprint, GMC controller |
| `edp/postgresql` | `ALTER ROLE` (`password` only; `admin_password` keeps its value) | EDP |
| `edp/redis` | `ACL SETUSER` | EDP |
| `user/edp-s3`, `user/sharepoint` | you write the new version first (`bao kv put`) | EDP |
| `user/hf-token` | you write the new version first | nothing; read at the next start or download |

Not rotatable (the run refuses them, giving the reason):

| Credential | Why |
|---|---|
| `keycloak/erag-admin`, `erag-user`, `erag-maintainer` | the configurator does not update existing users; users change their password in Keycloak |
| `nats/auth` | the NATS server and clients read the key only at start |
| `vector-db/redis` | Redis Cluster rotation (every node and `masterauth`) is not implemented |
| `vector-db/mssql` | the rotator has no SQL Server client |
| `edp/object-store` | how SeaweedFS reloads its S3 identities is unverified |
| `seaweedfs/admin` | how the SeaweedFS chart reloads it is unverified |
| `user/keycloak-oidc`, `user/ldap-bind` | write a new version, then run a normal `install erag`; the configurator applies it |

## Teardown

`./es_auto_installer.sh teardown erag --env <name>` with the backend on also:

- deletes **everything** under `<cluster_id>/erag/` in OpenBao, every version and the
  metadata. This includes your `erag/user/*` entries, and there is no option to keep
  them. Write them again before a reinstall;
- deletes the erag `ExternalSecret`s and the Secrets they own, also in namespaces erag
  does not delete (keycloak, monitoring, the model namespace);
- removes the `secrets.ai-solutions/erag` label and paths annotation from every
  namespace. It deletes namespace `erag-secrets` when the installer created it. Otherwise
  it keeps the namespace and deletes only its own objects there.

OpenBao is checked first, before any erag component is removed: the teardown stops with
"teardown stopped before removing anything" when OpenBao is sealed, unreachable or not
initialized, or the `erag-secrets-worker` role cannot log in. Unseal (or repair) it and
re-run, or delete the entries by hand with a root token
(`bao kv metadata delete -mount=intel-ai <cluster_id>/erag/<path>`).

If the OpenBao of the env is gone for good (the platform was torn down first, or the
store is lost), tell the teardown so:

```bash
./es_auto_installer.sh teardown erag --env <name> -- -e erag_teardown_store_lost=true
```

It skips the OpenBao check and the OpenBao delete, and still removes everything in the
cluster: the components, the erag `ExternalSecret`s and their Secrets, the labels and
annotation, `erag-secrets`, leftover importer/rotator RBAC, the deployment manifest and
the log directories. It warns that nothing was deleted from OpenBao. If that store still
exists somewhere (a restored backup, an external OpenBao), delete every entry under
`<cluster_id>/erag/` there, `erag/user/*` included: `bao kv list` each level, then
`bao kv metadata delete -mount=intel-ai <cluster_id>/erag/<path>` for each entry.

Pass the flag on the command line for that one run only, never in `config.erag.yaml`: on
a healthy OpenBao it would skip the delete and leave every credential behind.

## Backup and restore

With internal OpenBao, the erag backup profile ([Backup and Restore](../operate/backup.md))
includes the OpenBao Raft snapshot: namespace `openbao-backup` comes first, and the
snapshot hooks run before the backup and first after the restore. A restore therefore
brings back credentials that match the restored databases. Two things follow:

- The snapshot covers the whole OpenBao: a restore rolls back **every layer's** paths,
  not only erag's. Credentials created or rotated after the backup are gone.
- It is encrypted. Only the unseal shares of the OpenBao that took it can open it, and
  the shares are in no backup. Restoring into a rebuilt cluster needs the original
  shares.

Details: [platform runbook, Backup and restore](https://github.com/intel/enterprise-ai-solutions/blob/main/docs/deploy/openbao.md#backup-and-restore).
With external OpenBao the hooks do nothing: backing up your OpenBao is up to you, and it
must be consistent with the erag backups.

## External OpenBao, route and CA bundle

These are platform settings, described in the platform runbook:

- [External OpenBao](https://github.com/intel/enterprise-ai-solutions/blob/main/docs/deploy/openbao.md#external-openbao):
  `openbao_mode: external`, `openbao_address`, `openbao_ca_file`, `openbao_cluster_id`
  (required and unique per cluster) and the template that creates the roles. The erag
  roles are `erag-secrets-worker` and `erag-secrets-importer` (ServiceAccounts of the
  same name in `erag-secrets`) and `eso-erag`.
- [Route](https://github.com/intel/enterprise-ai-solutions/blob/main/docs/deploy/openbao.md#route):
  `openbao_route_enabled: true` publishes `https://openbao.<base_domain_name>` for the
  `bao` CLI (internal mode).
- CA bundle: the platform creates ConfigMap `openbao/openbao-ca-bundle` (key `ca.crt`),
  and erag copies it to `erag-secrets` for its Jobs. After the internal CA is renewed,
  re-run the platform install, then `install erag`.
- [Unseal after a restart](https://github.com/intel/enterprise-ai-solutions/blob/main/docs/deploy/openbao.md#unseal-after-a-restart).

## Known limitations

- **Changes outside OpenBao.** OpenBao is the only source.
  - A change made elsewhere is not picked up. Examples are a client secret regenerated
    in the Keycloak UI, a password changed in a database or a user password changed by
    hand. The service and OpenBao then disagree. For the Keycloak clients erag manages
    (`mcp-client`, `grafana-oauth`, the EDP OIDC client), `./es_auto_installer.sh validate
    erag` reports the drift by client name, and a normal `install erag` sets the OpenBao
    value on Keycloak again. The check needs the admin Secret and its Job image (see
    [In-cluster Jobs](#in-cluster-jobs-and-their-images)); when it cannot run, validate
    prints a WARNING that the check was not done. For anything else, write the new value to OpenBao (or rotate
    the id).
  - A change to a projected Secret (`kubectl edit`) is undone: ESO watches the Secrets it
    owns and restores the OpenBao value within about a second (event `secret updated`). A
    deleted one (`kubectl delete secret`) is recreated by ESO from OpenBao.
    There is no admission block; change the value in OpenBao (`bao kv patch`, or a
    [rotation](#rotate-a-credential)).
- **One `secrets_backend` per env.** The key is global: every layer and solution of the
  env uses the same backend. Switching an env from `openbao` back to `local` is not
  supported, and the install refuses it (see
  [Migrate an existing deployment](#migrate-an-existing-deployment)).
- An `erag/user/hf-token` that is deleted after it was projected leaves its projections,
  and the consumers keep the old token. Models that `model-manager` deploys into a
  namespace other than `inference_namespace` get no token.
- Without the env's OpenBao (the store is lost or the platform was torn down first) the
  teardown stops before removing any erag component, unless you pass
  `-e erag_teardown_store_lost=true` (see [Teardown](#teardown)).
- A migration or rotation run that is killed can leave its temporary Roles and
  RoleBindings behind: `erag-secrets-importer` in the legacy namespaces,
  `erag-secrets-rotator` in the keycloak namespace. They are limited to the Secrets they
  name (rotator: `get` on the Keycloak admin Secret; importer: `get`/`patch` on erag
  Secrets, `patch` on platform Secrets). The next `teardown erag` with the backend on
  removes them (label `app.kubernetes.io/part-of=erag-secrets`). To remove them earlier:
  `kubectl delete role,rolebinding -A -l app.kubernetes.io/part-of=erag-secrets`.
- `edp_rbac_enabled` (SeaweedFS IAM with Keycloak STS) is not supported with the
  backend on.
