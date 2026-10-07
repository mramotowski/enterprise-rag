#!/usr/bin/python
# Copyright (C) 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0
"""Test double for kubernetes.core.k8s_log (app_secrets tests only).

Returns the lines the FAKE_K8S_ON_APPLY hook stored for a Job under the key
"JobLog/<namespace>/<name>" of the JSON state file (see k8s.py).
"""

import json
import os

from ansible.module_utils.basic import AnsibleModule


def main():
    module = AnsibleModule(
        argument_spec=dict(
            api_version=dict(type="str", default="v1"),
            kind=dict(type="str", default="Pod"),
            name=dict(type="str", required=True),
            namespace=dict(type="str", required=True),
            container=dict(type="str"),
        ),
        supports_check_mode=True,
    )
    path = os.environ.get("FAKE_K8S_STATE")
    if not path:
        module.fail_json(msg="fake kubernetes.core.k8s_log: FAKE_K8S_STATE is not set")
    state = {}
    if os.path.exists(path):
        with open(path, encoding="utf-8") as handle:
            state = json.load(handle)
    params = module.params
    entry = state.get("JobLog/%s/%s" % (params["namespace"], params["name"]))
    if entry is None:
        module.fail_json(msg="fake kubernetes.core.k8s_log: no log for %s/%s" % (params["namespace"], params["name"]))
    lines = entry.get("lines", [])
    module.exit_json(changed=False, log="\n".join(lines), log_lines=lines)


if __name__ == "__main__":
    main()
