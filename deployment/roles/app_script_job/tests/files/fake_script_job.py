#!/usr/bin/env python3
# Copyright (C) 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0
"""FAKE_K8S_ON_APPLY hook of tests/test_script_job_callers.yaml: for a Job key,
keeps the Job and its ConfigMap as FakeRendered/<ns>/<name> (the runner deletes
both), logs the line FAKE_JOB_LOG and marks the Job succeeded."""

import json
import os
import sys

path, key = sys.argv[1], sys.argv[2]
if key.startswith("Job/"):
    with open(path, encoding="utf-8") as handle:
        state = json.load(handle)
    ns_name = key.split("/", 1)[1]
    state["FakeRendered/" + ns_name] = {"job": state[key], "configmap": state.get("ConfigMap/" + ns_name)}
    state["JobLog/" + ns_name] = {"lines": [os.environ.get("FAKE_JOB_LOG", "")]}
    state[key]["status"] = {"succeeded": 1}
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(state, handle)
