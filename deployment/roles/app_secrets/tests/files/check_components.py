#!/usr/bin/env python3
# Copyright (C) 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0
"""Test helper (rotation_cases.yaml).

    check_components.py <components.yaml>
        renders the `enabled` switch of every component for a few variable
        sets, as the ai-solutions preflight does (Jinja; absent = enabled;
        "True"/"False" strings coerced), and prints {scenario: [enabled
        component names]} as JSON.
    check_components.py --rotate-branch <app_pre_install tasks/install.yaml>
        prints {"branch": <index of the rotate include or -1>, "unguarded":
        [names of the tasks after it whose when lacks the rotate-run guard]}."""

import json
import sys

import jinja2
import yaml


def to_bool(value):
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("yes", "on", "1", "true", "y")


def main(path):
    with open(path, encoding="utf-8") as handle:
        comps = yaml.safe_load(handle)["components"]
    env = jinja2.Environment(undefined=jinja2.ChainableUndefined)
    env.filters["bool"] = to_bool
    flags = {"vector_databases_enabled": True, "chat_history_enabled": True, "edp_enabled": True,
             "mcp_enabled": True, "ui_enabled": True}
    scenarios = {"default": {}, "all_on": flags, "rotate": dict(flags, erag_rotate="[edp/redis]"),
                 "rotate_empty_string": {"erag_rotate": ""},
                 "rotate_teardown": dict(flags, erag_rotate="[edp/redis]", component_action="teardown")}
    out = {"all_names": [c["name"] for c in comps]}
    for name, variables in scenarios.items():
        enabled = []
        for comp in comps:
            switch = comp.get("enabled", True)
            if isinstance(switch, str):
                switch = to_bool(env.from_string(switch).render(**variables))
            if switch:
                enabled.append(comp["name"])
        out[name] = enabled
    print(json.dumps(out))


GUARD = "not (app_pre_install_rotate_run | bool)"


def rotate_branch(path):
    with open(path, encoding="utf-8") as handle:
        tasks = yaml.safe_load(handle)
    branch = next((i for i, t in enumerate(tasks)
                   if (t.get("ansible.builtin.include_tasks") or {}).get("file") == "rotate.yaml"), -1)
    unguarded = []
    for task in tasks[branch + 1:] if branch >= 0 else []:
        when = task.get("when", [])
        when = [when] if isinstance(when, str) else when
        if GUARD not in when:
            unguarded.append(task.get("name"))
    print(json.dumps({"branch": branch, "unguarded": unguarded}))


if __name__ == "__main__":
    if sys.argv[1] == "--rotate-branch":
        rotate_branch(sys.argv[2])
    else:
        main(sys.argv[1])
