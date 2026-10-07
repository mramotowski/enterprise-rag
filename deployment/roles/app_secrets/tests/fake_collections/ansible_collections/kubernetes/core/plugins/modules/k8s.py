#!/usr/bin/python
# Copyright (C) 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0
"""Test double for kubernetes.core.k8s (app_secrets tests only).

Keeps objects in the JSON file named by the FAKE_K8S_STATE environment
variable, keyed "<kind>/<namespace>/<name>". state=present deep-merges the
definition into an existing object (labels, annotations and data merge key
by key, as a merge patch does: a null value removes the key) or creates it;
state=patched merges the same way into an existing object only; state=absent
deletes it, and plays the garbage collector: deleting a Namespace deletes
every object in it, deleting an ExternalSecret deletes the Secrets that name
it in ownerReferences unless delete_options.propagationPolicy is Orphan. The
propagation policy of every ExternalSecret delete is recorded in
"FakeDeletes//ExternalSecret" (policies: [...]) for the tests.
definition may be one object or a list; src is a (multi-document) YAML file.

When FAKE_K8S_ON_APPLY is set, it is run as "<FAKE_K8S_ON_APPLY> <state file>
<key>" after a Job or ExternalSecret is applied, to play the Job (or ESO), after
an ExternalSecret is patched (ESO reacts to the force-sync annotation), and after
a Deployment, StatefulSet or DaemonSet spec is patched (the controller rolls it
out). A spec change of those kinds bumps metadata.generation, as the API server
does.
"""

import copy
import json
import os
import shlex
import subprocess

from ansible.module_utils.basic import AnsibleModule


WORKLOADS = ("Deployment", "StatefulSet", "DaemonSet")


def _load(path):
    if not os.path.exists(path):
        return {}
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def _save(path, state):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump(state, handle, indent=1, sort_keys=True)
    os.replace(tmp, path)


def _merge(base, patch):
    out = copy.deepcopy(base)
    for key, value in patch.items():
        if value is None:
            out.pop(key, None)
        elif isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _merge(out[key], value)
        else:
            out[key] = copy.deepcopy(value)
    return out


def main():
    module = AnsibleModule(
        argument_spec=dict(
            state=dict(type="str", default="present", choices=["present", "absent", "patched"]),
            definition=dict(type="raw"),
            merge_type=dict(type="raw"),
            api_version=dict(type="str", default="v1"),
            kind=dict(type="str"),
            name=dict(type="str"),
            namespace=dict(type="str"),
            src=dict(type="path"),
            wait=dict(type="bool", default=False),
            wait_timeout=dict(type="int", default=120),
            delete_options=dict(type="raw"),
            apply=dict(type="bool", default=False),
        ),
        supports_check_mode=False,
    )
    path = os.environ.get("FAKE_K8S_STATE")
    if not path:
        module.fail_json(msg="fake kubernetes.core.k8s: FAKE_K8S_STATE is not set")
    params = module.params
    definitions = params["definition"]
    if params["src"]:
        import yaml  # PyYAML ships with ansible-core

        with open(params["src"], encoding="utf-8") as handle:
            definitions = [d for d in yaml.safe_load_all(handle) if d]
    if isinstance(definitions, str):
        definitions = json.loads(definitions)
    if definitions is None:
        definitions = [{}]
    if isinstance(definitions, dict):
        definitions = [definitions]

    changed = False
    results = []
    hooks = []
    for definition in definitions:
        key, after, did_change = _apply(module, path, params, definition)
        changed = changed or did_change
        results.append(after)
        kind = key.split("/", 1)[0] if key else ""
        if kind in ("Job", "ExternalSecret") and params["state"] == "present":
            hooks.append(key)
        elif kind == "ExternalSecret" and params["state"] == "patched" and did_change:
            hooks.append(key)
        elif kind in WORKLOADS and params["state"] == "patched" and did_change and "spec" in definition:
            hooks.append(key)
    hook = os.environ.get("FAKE_K8S_ON_APPLY")
    for key in hooks:
        if hook:
            run = subprocess.run(shlex.split(hook) + [path, key], capture_output=True, text=True, check=False)
            if run.returncode != 0:
                module.fail_json(msg="fake kubernetes.core.k8s: hook failed for %s: %s" % (key, run.stderr[-2000:]))
    module.exit_json(changed=changed, result=results[0] if len(results) == 1 else results)


def _apply(module, path, params, definition):
    meta = definition.get("metadata", {})
    kind = definition.get("kind") or params["kind"]
    name = meta.get("name") or params["name"]
    namespace = meta.get("namespace") or params["namespace"] or ""
    if not kind or not name:
        module.fail_json(msg="fake kubernetes.core.k8s: kind and name are required")
    if kind in ("Namespace", "ClusterSecretStore"):
        namespace = ""
    key = "%s/%s/%s" % (kind, namespace, name)

    state = _load(path)
    before = state.get(key)
    if params["state"] == "absent":
        if before is not None:
            del state[key]
            policy = (params["delete_options"] or {}).get("propagationPolicy", "Background")
            if kind == "ExternalSecret":
                state.setdefault("FakeDeletes//ExternalSecret", {"policies": []})["policies"].append(policy)
            for other in list(state):
                o_kind, o_ns, _o_name = (other.split("/", 2) + ["", ""])[:3]
                # JobLog/ and Fake* keys are test records, not cluster objects.
                if o_kind == "JobLog" or o_kind.startswith("Fake"):
                    continue
                in_namespace = kind == "Namespace" and o_ns == name
                owned = kind == "ExternalSecret" and policy != "Orphan" and o_kind == "Secret" and o_ns == namespace and any(
                    ref.get("kind") == "ExternalSecret" and ref.get("name") == name
                    for ref in (state[other].get("metadata", {}).get("ownerReferences") or []))
                if in_namespace or owned:
                    del state[other]
            _save(path, state)
        return key, {}, before is not None

    if before is None and params["state"] == "patched":
        module.fail_json(msg="fake kubernetes.core.k8s: %s does not exist (state patched)" % key)
    if before is None:
        after = copy.deepcopy(definition)
        after.setdefault("apiVersion", params["api_version"])
        after.setdefault("kind", kind)
        after.setdefault("metadata", {}).update({"name": name, "namespace": namespace})
    else:
        after = _merge(before, definition)
        if params["apply"] and "spec" in definition:
            after["spec"] = copy.deepcopy(definition["spec"])
        if kind in WORKLOADS and after.get("spec") != before.get("spec"):
            meta_after = after.setdefault("metadata", {})
            meta_after["generation"] = int(meta_after.get("generation", 1)) + 1
    if after != before:
        state[key] = after
        _save(path, state)
    return key, after, after != before


if __name__ == "__main__":
    main()
