#!/usr/bin/env python3
# Copyright (C) 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0
"""FAKE_K8S_ON_APPLY hook for tests/test_vector_dims_job.yaml (tests only).

    fake_vector_dims_job.py <state file> <key>

For a Job key: runs the Job's container command on this host with exactly the
container env (values, and secretKeyRef from the Secrets in the fake state;
a missing optional ref is left out, as the kubelet does) and the script from
the Job's ConfigMap volume. urllib.request.urlopen is replaced in the child:
it answers from FAKE_HF_DIMS (JSON {model_id: hidden_size}; any other model
gets HTTP 404) and records the Authorization header in a private file. The
hook then stores, without any value:
  JobLog/<ns>/<name>         {lines: the container's stdout and stderr lines}
  FakeVectorDimsRun/<ns>/<name>
                             {argv, env_names, auth: none | token-from-secret | other}
and sets the Job status succeeded / failed. FAKE_JOB_FAIL=1 makes the
container exit 1; FAKE_JOB_DEADLINE=1 leaves no pod and sets the Job's Failed
condition (DeadlineExceeded) only. A missing non-optional secretKeyRef leaves
the pod unstarted (CreateContainerConfigError): the Job gets no status.
Other keys are ignored.
"""

import base64
import json
import os
import subprocess
import sys
import tempfile

WRAPPER = r"""
import io, json, os, runpy, sys, urllib.error, urllib.request
dims = json.loads(os.environ.pop("FAKE_HF_DIMS_JSON", "{}"))
record = os.environ.pop("FAKE_HF_RECORD")
def fake_urlopen(req, timeout=None):
    auth = req.get_header("Authorization")
    with open(record, "w", encoding="utf-8") as handle:
        handle.write(auth or "")
    model = req.full_url.split("huggingface.co/", 1)[1].rsplit("/resolve/", 1)[0]
    if model not in dims:
        raise urllib.error.HTTPError(req.full_url, 404, "not found", {}, None)
    body = json.dumps({"hidden_size": dims[model]}).encode()
    class R(io.BytesIO):
        def __enter__(self): return self
        def __exit__(self, *a): return False
    return R(body)
urllib.request.urlopen = fake_urlopen
script = sys.argv[1]
sys.argv = sys.argv[1:]
runpy.run_path(script, run_name="__main__")
"""


def secret_value(state, namespace, ref):
    secret = state.get(f"Secret/{namespace}/{ref['name']}")
    if secret is None:
        return None
    if ref["key"] in (secret.get("stringData") or {}):
        return secret["stringData"][ref["key"]]
    data = secret.get("data") or {}
    if ref["key"] in data:
        return base64.b64decode(data[ref["key"]]).decode()
    return None


def main():
    path, key = sys.argv[1], sys.argv[2]
    if not key.startswith("Job/"):
        return 0
    with open(path, encoding="utf-8") as handle:
        state = json.load(handle)
    job = state[key]
    _, namespace, name = key.split("/", 2)
    pod = job["spec"]["template"]["spec"]
    container = pod["containers"][0]
    volume = next(v for v in pod["volumes"] if "configMap" in v)
    mount = next(m for m in container["volumeMounts"] if m["name"] == volume["name"])
    cm = state[f"ConfigMap/{namespace}/{volume['configMap']['name']}"]

    if os.environ.get("FAKE_JOB_DEADLINE"):
        job["status"] = {
            "conditions": [
                {
                    "type": "Failed",
                    "status": "True",
                    "reason": "DeadlineExceeded",
                    "message": "Job was active longer than specified deadline",
                }
            ]
        }
        save(path, state)
        return 0

    env, token, optional = {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}, None, {}
    for item in container.get("env", []):
        if "value" in item:
            env[item["name"]] = item["value"]
            continue
        ref = item["valueFrom"]["secretKeyRef"]
        optional[ref["name"]] = bool(ref.get("optional"))
        value = secret_value(state, namespace, ref)
        if value is None:
            if not ref.get("optional"):
                state[f"FakeVectorDimsRun/{namespace}/{name}"] = {
                    "argv": [],
                    "env_names": [],
                    "auth": "none",
                    "rc": None,
                    "optional": optional,
                    "unstarted": True,
                }
                save(path, state)
                return 0
            continue
        env[item["name"]] = value
        if ref["name"] == "hf-token":
            token = value

    with tempfile.TemporaryDirectory() as work:
        os.chmod(work, 0o700)
        script_dir = os.path.join(work, "script")
        os.mkdir(script_dir)
        for file_name, text in cm["data"].items():
            with open(
                os.path.join(script_dir, file_name), "w", encoding="utf-8"
            ) as handle:
                handle.write(text)
        command = container["command"] + container.get("args", [])
        script = command[1].replace(mount["mountPath"], script_dir, 1)
        record = os.path.join(work, "auth")
        child_env = dict(
            env,
            FAKE_HF_DIMS_JSON=os.environ.get("FAKE_HF_DIMS", "{}"),
            FAKE_HF_RECORD=record,
        )
        if os.environ.get("FAKE_JOB_FAIL"):
            run = subprocess.run(
                [sys.executable, "-c", "import sys; sys.exit('boom')"],
                capture_output=True,
                text=True,
                check=False,
            )
        else:
            run = subprocess.run(
                [sys.executable, "-c", WRAPPER, script] + command[2:],
                env=child_env,
                capture_output=True,
                text=True,
                check=False,
            )
        auth = "none"
        if os.path.exists(record):
            with open(record, encoding="utf-8") as handle:
                header = handle.read()
            if header:
                auth = (
                    "token-from-secret"
                    if token and header == "Bearer " + token
                    else "other"
                )

    state[f"JobLog/{namespace}/{name}"] = {
        "lines": (run.stderr + run.stdout).splitlines()
    }
    state[f"FakeVectorDimsRun/{namespace}/{name}"] = {
        "argv": command,
        "env_names": sorted(env),
        "auth": auth,
        "rc": run.returncode,
        "optional": optional,
    }
    job["status"] = {"succeeded": 1} if run.returncode == 0 else {"failed": 1}
    save(path, state)
    return 0


def save(path, state):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump(state, handle, indent=1, sort_keys=True)
    os.replace(tmp, path)


if __name__ == "__main__":
    sys.exit(main())
