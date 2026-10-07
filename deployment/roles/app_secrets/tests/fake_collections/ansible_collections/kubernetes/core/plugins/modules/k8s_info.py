#!/usr/bin/python
# Copyright (C) 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0
"""Test double for kubernetes.core.k8s_info (app_secrets tests only).

Reads the JSON file named by FAKE_K8S_STATE (see k8s.py). Filters by kind,
then name/namespace, then label_selectors of the form "key=value". The
result carries fake: true so tests can check the double is in use. A status
the apply hook parked in _fake_final_status appears after _fake_polls_left reads.
"""

import json
import os

from ansible.module_utils.basic import AnsibleModule


def main():
    module = AnsibleModule(
        argument_spec=dict(
            api_version=dict(type="str", default="v1"),
            kind=dict(type="str", required=True),
            name=dict(type="str"),
            namespace=dict(type="str"),
            label_selectors=dict(type="list", elements="str", default=[]),
        ),
        supports_check_mode=True,
    )
    path = os.environ.get("FAKE_K8S_STATE")
    if not path:
        module.fail_json(msg="fake kubernetes.core.k8s_info: FAKE_K8S_STATE is not set")
    state = {}
    if os.path.exists(path):
        with open(path, encoding="utf-8") as handle:
            state = json.load(handle)
    params = module.params
    resources = []
    dirty = False
    for key in sorted(state):
        kind, namespace, name = key.split("/", 2)
        if kind != params["kind"]:
            continue
        if params["name"] and name != params["name"]:
            continue
        if params["namespace"] and namespace != params["namespace"]:
            continue
        labels = state[key].get("metadata", {}).get("labels", {}) or {}
        if any(labels.get(sel.split("=", 1)[0]) != sel.split("=", 1)[1] for sel in params["label_selectors"]):
            continue
        obj = state[key]
        if "_fake_final_status" in obj:
            # Status set by the FAKE_K8S_ON_APPLY hook, shown after <n> reads.
            obj["_fake_polls_left"] = obj.get("_fake_polls_left", 0) - 1
            if obj["_fake_polls_left"] <= 0:
                obj["status"] = obj.pop("_fake_final_status")
                obj.pop("_fake_polls_left")
            dirty = True
        resources.append({k: v for k, v in obj.items() if not k.startswith("_fake")})
    if dirty:
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as handle:
            json.dump(state, handle, indent=1, sort_keys=True)
        os.replace(tmp, path)
    module.exit_json(changed=False, resources=resources, fake=True)


if __name__ == "__main__":
    main()
