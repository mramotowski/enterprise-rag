#!/usr/bin/env python3
# Copyright (C) 2026 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

"""
Resolve the vector dimensions (hidden_size) for a given embedding model.

Keyed on the HuggingFace repo id (models.yaml -> model_id), not the model
catalog name, which is only the name KServe serves the model under.

Resolution order:
  1. Built-in lookup table of well-known models
  2. HuggingFace Hub API (skipped when --offline is set)

Outputs a single JSON object to stdout:
  {"vector_dims": <int>, "source": "<source>", "model": "<model_id>"}
"""

import json
import argparse
import os
import sys
import urllib.request
import urllib.error

# Built-in lookup table for well-known embedding models and their hidden sizes.
# Keep every embed model in deployment/models.yaml listed here so air-gapped
# installs resolve without the HuggingFace API.
KNOWN_MODEL_DIMS = {
    # BAAI BGE series
    "BAAI/bge-base-en-v1.5": 768,
    "BAAI/bge-large-en-v1.5": 1024,
    "BAAI/bge-m3": 1024,
    # Jina AI
    "jinaai/jina-embeddings-v2-small-en": 512,
    "jinaai/jina-embeddings-v2-base-en": 768,
    "jinaai/jina-embeddings-v2-large-en": 1024,
    "jinaai/jina-embeddings-v3": 1024,
    # Nomic AI
    "nomic-ai/nomic-embed-text-v1": 768,
    # intfloat E5
    "intfloat/multilingual-e5-large": 1024,
    "intfloat/multilingual-e5-large-instruct": 1024,
    # sdadas (Polish)
    "sdadas/stella-pl-retrieval-8k": 1024,
}


def _read_hidden_size_from_config(config_path):
    """Parse hidden_size from a model config.json file."""
    try:
        with open(config_path, "r", encoding="utf-8") as fh:
            config = json.load(fh)
        return config.get("hidden_size")
    except (OSError, json.JSONDecodeError):
        return None


def resolve_from_hf_api(model_id, hf_token=None):
    """Resolve hidden_size by fetching config.json from HuggingFace Hub API."""
    url = f"https://huggingface.co/{model_id}/resolve/main/config.json"
    headers = {"User-Agent": "resolve-vector-dims/1.0"}
    if hf_token:
        headers["Authorization"] = f"Bearer {hf_token}"
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=15) as response:  # nosec B310
            config = json.loads(response.read().decode("utf-8"))
        return config.get("hidden_size")
    except (urllib.error.URLError, json.JSONDecodeError, OSError):
        return None


def resolve_vector_dims(model_id, offline=False, hf_token=None):
    """
    Resolve the vector dimensions for the given embedding model.

    Returns a tuple (vector_dims: int | None, source: str | None).
    """
    # 1. Built-in lookup table (fast, works offline)
    if model_id in KNOWN_MODEL_DIMS:
        return KNOWN_MODEL_DIMS[model_id], "known_models_table"

    # 2. HuggingFace Hub API (requires network)
    if not offline:
        dims = resolve_from_hf_api(model_id, hf_token)
        if dims is not None:
            return dims, "huggingface_api"

    return None, None


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Resolve vector dimensions (hidden_size) for an embedding model. "
            "Outputs JSON: {\"vector_dims\": <int>, \"source\": \"<source>\", \"model\": \"<model_id>\"}"
        )
    )
    parser.add_argument(
        "--embedding-model-id",
        required=True,
        help="HuggingFace model identifier (e.g. BAAI/bge-base-en-v1.5)",
    )
    parser.add_argument(
        "--hf-token",
        default=None,
        help="HuggingFace API token for accessing gated models (optional)",
    )
    parser.add_argument(
        "--hf-token-env",
        default=None,
        metavar="NAME",
        help=(
            "Read the HuggingFace API token from this environment variable "
            "instead of --hf-token, so it never appears in argv (used by the "
            "in-cluster Job; an unset or empty variable means no token)"
        ),
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Skip the HuggingFace Hub API call (useful in air-gapped environments)",
    )
    parser.add_argument(
        "--fallback-dims",
        type=int,
        default=None,
        help=(
            "Fallback vector dims used when auto-detection fails. "
            "If omitted and detection fails, the script exits with an error."
        ),
    )

    args = parser.parse_args()

    hf_token = args.hf_token
    if args.hf_token_env:
        hf_token = os.environ.get(args.hf_token_env) or None

    vector_dims, source = resolve_vector_dims(
        model_id=args.embedding_model_id,
        offline=args.offline,
        hf_token=hf_token,
    )

    if vector_dims is None:
        if args.fallback_dims is not None:
            vector_dims = args.fallback_dims
            source = "fallback_config_value"
            print(
                f"WARNING: Could not auto-detect hidden_size for "
                f"'{args.embedding_model_id}'. "
                f"Using fallback value: {vector_dims}. "
                f"To fix this, either add the model to KNOWN_MODEL_DIMS in "
                f"roles/app_pre_install/files/resolve_vector_dims.py or set "
                f"vector_databases_vector_dims explicitly in config.yaml.",
                file=sys.stderr,
            )
        else:
            print(
                f"ERROR: Could not determine hidden_size for embedding model "
                f"'{args.embedding_model_id}'.\n"
                f"Tried: known_models_table, "
                f"huggingface_api.\n"
                f"To resolve:\n"
                f"  1. Add the model to KNOWN_MODEL_DIMS in "
                f"     deployment/roles/app_pre_install/files/resolve_vector_dims.py\n"
                f"  2. Set vector_dims explicitly in config.yaml under vector_databases",
                file=sys.stderr,
            )
            sys.exit(1)

    result = {
        "vector_dims": vector_dims,
        "source": source,
        "model": args.embedding_model_id,
    }
    sys.stdout.write(json.dumps(result))


if __name__ == "__main__":
    main()
