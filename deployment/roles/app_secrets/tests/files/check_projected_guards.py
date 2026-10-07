#!/usr/bin/env python3
# Copyright (C) 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0
"""Static check for test_role_calls.yaml: in the given role task files, every
kubernetes.core.k8s task that writes or deletes a Secret must be skipped when the port
projects Secrets, i.e. its own `when` or an enclosing block's `when` must hold
a condition "not (app_secrets_projected ...)" or "not app_secrets_projected"
(the ESO projections own those Secrets then).

    check_projected_guards.py <allowed-secret-name>,... <tasks.yaml> ...

Prints one line per unguarded Secret write ("unguarded <file>: <task name>"),
then "checked <n>" (the Secret writes found), and exits 1 when any is
unguarded; allowed names (local by design, e.g. seaweedfs-iam-config) are
skipped.
"""

import sys

import yaml  # PyYAML ships with ansible-core

MODULES = ("kubernetes.core.k8s", "k8s")


def conditions(task):
    when = task.get("when", [])
    return [str(w) for w in (when if isinstance(when, list) else [when])]


def walk(tasks, inherited, path, allowed, bad, checked):
    for task in tasks or []:
        if not isinstance(task, dict):
            continue
        conds = inherited + conditions(task)
        if any(k in task for k in ("block", "rescue", "always")):
            for key in ("block", "rescue", "always"):
                walk(task.get(key), conds, path, allowed, bad, checked)
            continue
        module = next((task[m] for m in MODULES if m in task), None)
        # A deletion counts too: ESO would recreate a deleted projection only later.
        if not isinstance(module, dict) or module.get("state", "present") not in ("present", "absent"):
            continue
        definition = module.get("definition")
        if not isinstance(definition, dict):
            definition = {"kind": module.get("kind"), "metadata": {"name": module.get("name", "")}}
        if definition.get("kind") != "Secret":
            continue
        if str(definition.get("metadata", {}).get("name", "")) in allowed:
            continue
        checked.append(path)
        if not any(c.strip().startswith(("not (app_secrets_projected", "not app_secrets_projected")) for c in conds):
            bad.append("unguarded %s: %s" % (path, task.get("name", "?")))


def main():
    allowed = set(filter(None, sys.argv[1].split(",")))
    bad, checked = [], []
    for path in sys.argv[2:]:
        with open(path, encoding="utf-8") as handle:
            walk(yaml.safe_load(handle), [], path, allowed, bad, checked)
    for line in bad:
        print(line)
    print("checked %d" % len(checked))
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
