"""Identity of the inputs that decide a verdict.

A signed bundle covers the evidence and the outcome. These helpers name the
rubric, the knowledge base, and the engine that turned one into the other, so a
third party can re-run the engine against exactly what the bundle names.

Values come from two places:

  * the engine's own version, from installed package metadata with the source
    revision appended when the checkout has one
  * ``commitments.json`` at the engine root, written by
    ``scripts/publish_commitments.py`` (rubric and knowledge base content hashes)

An empty string means the value was never recorded, which is the honest reading
for a bundle signed before the manifest existed. Such a bundle cannot be
re-derived.
"""

from __future__ import annotations

import json
import subprocess
from functools import lru_cache
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
COMMITMENTS_PATH = PROJECT_ROOT / "commitments.json"

BUNDLE_SCHEMA_VERSION = 1
UNSPECIFIED = "unspecified"


@lru_cache(maxsize=1)
def source_revision() -> str:
    """Short revision of the checkout, or an empty string when unavailable."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--short=7", "HEAD"],
            cwd=PROJECT_ROOT,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return result.stdout.strip() if result.returncode == 0 else ""


@lru_cache(maxsize=1)
def engine_version() -> str:
    """Package version, carrying the source revision when there is one."""
    try:
        from importlib.metadata import version

        base = version("confidior-engine")
    except Exception:
        base = "unknown"
    revision = source_revision()
    return f"{base}+g{revision}" if revision else base


@lru_cache(maxsize=1)
def commitments() -> dict:
    """The published commitments, or an empty mapping when none exist."""
    if not COMMITMENTS_PATH.is_file():
        return {}
    try:
        return json.loads(COMMITMENTS_PATH.read_text())
    except (OSError, json.JSONDecodeError):
        return {}


def _artifact_version(role: str) -> str:
    """``<label>@sha256:<hash>`` for a published artifact, else empty."""
    for artifact in commitments().get("artifacts", []):
        if artifact.get("role") == role:
            return f"{artifact['label']}@sha256:{artifact['sha256']}"
    return ""


def rubric_version() -> str:
    """The published rubric commitment, else an empty string."""
    return _artifact_version("rubric")


def knowledge_base_version() -> str:
    """The published knowledge base commitment, else an empty string."""
    return _artifact_version("knowledge_base")


def bundle_manifest(
    weight_profile: str = "",
    policy_version: str = UNSPECIFIED,
) -> dict[str, str]:
    """The version manifest recorded on every bundle created from now on."""
    return {
        "engine_version": engine_version(),
        "schema_version": str(BUNDLE_SCHEMA_VERSION),
        "weight_profile": weight_profile,
        "policy_version": policy_version,
        "rubric_version": rubric_version(),
        "knowledge_base_version": knowledge_base_version(),
    }
