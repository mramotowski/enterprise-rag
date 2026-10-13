#!/usr/bin/env python3
# Copyright (C) 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0
"""Static checks for test_port_contract.yaml, on role task files.

    check_projected_guards.py <allowed-secret-name>,... <tasks.yaml> ...

Every kubernetes.core.k8s task that writes or deletes a Secret must be skipped
when the port projects Secrets (the ESO projections own those Secrets then):
its own `when` or an enclosing block's `when` must hold a local guard (below).
Allowed names (local by design, e.g. seaweedfs-iam-config) are skipped.

    check_projected_guards.py --port-calls <tasks.yaml> ...

Every app_secrets port call (include_role or import_role, tasks_from probe,
ensure, status, delete, import or rotate, with or without .yaml) must run only
when the port projects Secrets: its own or an enclosing `when` holds
"app_secrets_projected" or "app_secrets_projected | bool" (the port is openbao
only).

    check_projected_guards.py --local-calls <tasks.yaml> ...

Every include/import of app_generate_password or app_password_mgmt, and every
task that writes a default_credentials.* file, must be skipped when the port
projects Secrets (local guard).

A local guard is a condition starting "not app_secrets_projected" or
"not (app_secrets_projected". A guard with a default() does not count: a
missing fact must fail, not fall back to a path.

Prints "found <file>: <task name>" per checked task, "unguarded <file>: <task
name>" per task without its guard, then "checked <n>" (the tasks found), and
exits 1 when any is unguarded or no file is given, 2 on a usage error.
"""

import json
import sys

import yaml  # PyYAML ships with ansible-core

USAGE = [line for line in __doc__.splitlines() if line.startswith("    check_projected_guards.py")]
K8S = ("kubernetes.core.k8s", "k8s")
ROLE_CALLS = ("ansible.builtin.include_role", "include_role", "ansible.builtin.import_role", "import_role")
PORT_OPS = ("probe", "ensure", "status", "delete", "import", "rotate")
LOCAL_HELPERS = ("app_generate_password", "app_password_mgmt")
BLOCK_KEYS = ("block", "rescue", "always")


def conditions(task):
    when = task.get("when", [])
    return [str(w).strip() for w in (when if isinstance(when, list) else [when])]


def local_guard(conds):
    return any(c.startswith(("not (app_secrets_projected", "not app_secrets_projected")) and "default(" not in c
               for c in conds)


def projected_guard(conds):
    return any(c in ("app_secrets_projected", "app_secrets_projected | bool") for c in conds)


def role_call(task):
    call = next((task[m] for m in ROLE_CALLS if m in task), None)
    return call if isinstance(call, dict) else None


def secret_write(task, allowed):
    module = next((task[m] for m in K8S if m in task), None)
    # A deletion counts too: ESO would recreate a deleted projection only later.
    if not isinstance(module, dict) or module.get("state", "present") not in ("present", "absent"):
        return False
    definition = module.get("definition")
    if not isinstance(definition, dict):
        definition = {"kind": module.get("kind"), "metadata": {"name": module.get("name", "")}}
    return (definition.get("kind") == "Secret"
            and str(definition.get("metadata", {}).get("name", "")) not in allowed)


def port_call(task):
    call = role_call(task)
    return (call is not None and call.get("name") == "app_secrets"
            and str(call.get("tasks_from", "")).removesuffix(".yaml") in PORT_OPS)


def local_call(task):
    call = role_call(task)
    if call is not None:
        return call.get("name") in LOCAL_HELPERS
    # Any module whose arguments name the file (copy dest, lineinfile path, ...).
    return any("default_credentials." in json.dumps(v, default=str)
               for k, v in task.items() if k not in ("name", "when", "vars"))


def walk(tasks, inherited, path, select, guarded, bad, checked):
    for task in tasks or []:
        if not isinstance(task, dict):
            continue
        conds = inherited + conditions(task)
        if any(k in task for k in BLOCK_KEYS):
            for key in BLOCK_KEYS:
                walk(task.get(key), conds, path, select, guarded, bad, checked)
            continue
        if not select(task):
            continue
        name = "%s: %s" % (path, task.get("name", "?"))
        checked.append(name)
        if not guarded(conds):
            bad.append(name)


def main(argv):
    if not argv:
        print("usage:\n" + "\n".join(USAGE), file=sys.stderr)
        sys.exit(2)
    if argv[0] == "--port-calls":
        select, guarded = port_call, projected_guard
    elif argv[0] == "--local-calls":
        select, guarded = local_call, local_guard
    elif argv[0].startswith("-"):
        print("unknown option %s\nusage:\n%s" % (argv[0], "\n".join(USAGE)), file=sys.stderr)
        sys.exit(2)
    else:
        allowed = set(filter(None, argv[0].split(",")))
        select, guarded = (lambda task: secret_write(task, allowed)), local_guard
    paths = argv[1:]
    bad, checked = [], []
    for path in paths:
        with open(path, encoding="utf-8") as handle:
            walk(yaml.safe_load(handle), [], path, select, guarded, bad, checked)
    for line in checked:
        print("found " + line)
    for line in bad:
        print("unguarded " + line)
    print("checked %d" % len(checked))
    if not paths:
        print("no task file given", file=sys.stderr)
    sys.exit(1 if bad or not paths else 0)


if __name__ == "__main__":
    main(sys.argv[1:])
