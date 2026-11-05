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

import hashlib
import json
import subprocess
from functools import lru_cache
from pathlib import Path
from typing import Any, Sequence, TypedDict

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
    """The published commitments, or an empty mapping when the file is absent.

    An absent file is a legitimate state -- nothing has been published yet -- and
    yields an empty mapping, so the version fields simply read as unset. A file
    that exists but cannot be parsed *raises*, matching ``load_trust_root``: both
    are operator configuration, and a bundle that quietly reports "no rubric
    commitment" when a malformed file is sitting on disk is asserting something
    false about what it was built from.
    """
    if not COMMITMENTS_PATH.is_file():
        return {}
    try:
        data = json.loads(COMMITMENTS_PATH.read_text())
    except (OSError, json.JSONDecodeError) as e:
        raise ValueError(f"{COMMITMENTS_PATH} exists but is not readable JSON: {e}") from e
    if not isinstance(data, dict):
        raise ValueError(f"{COMMITMENTS_PATH} must contain a JSON object")
    return data


def _artifact_commitments() -> dict[str, dict[str, str]]:
    """Published commitments keyed by role, each with a resolvable location.

    The label is the repository-relative path the artifact is published at, so
    a reader can fetch it and confirm the hash matches, the "published
    location" resolution path in docs/ARTIFACT-IDENTITY.md.
    """
    out: dict[str, dict[str, str]] = {}
    for artifact in commitments().get("artifacts", []):
        role = artifact.get("role")
        if not role:
            continue
        out[role] = {
            "label": artifact.get("label", ""),
            "sha256": artifact.get("sha256", ""),
            "location": artifact.get("label", ""),
        }
    return out


def _artifact_version(role: str) -> str:
    """``<label>@sha256:<hash>`` for a published artifact, else empty."""
    artifact = _artifact_commitments().get(role)
    if artifact:
        return f"{artifact['label']}@sha256:{artifact['sha256']}"
    return ""


def rubric_version() -> str:
    """The published rubric commitment, else an empty string."""
    return _artifact_version("rubric")


def knowledge_base_version() -> str:
    """The published knowledge base commitment, else an empty string."""
    return _artifact_version("knowledge_base")


def weights_hash(profile_name: str) -> str:
    """Content hash of a score profile's weights and grade thresholds.

    The profile is a published input to the verdict: two runs with different
    weights are different claims. It is a small dict, so its canonical JSON is
    hashed directly rather than committed to a file.

    Imported lazily: ``src.core.risk`` imports this module's callers, and the
    profile data lives there.
    """
    from src.core.risk import _get_score_profile

    profile = _get_score_profile(profile_name)
    canonical = json.dumps(
        {
            "name": profile.name,
            "weights": profile.weights,
            "grade_thresholds": profile.grade_thresholds,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return f"sha256:{_sha256(canonical.encode('utf-8'))}"


def policy_hash(rules: Sequence[Any]) -> str:
    """Content hash of the rules a verdict was actually evaluated against.

    Hashes the evaluated rules rather than the file they were loaded from, so
    a policy edited after the run cannot be passed off as the one behind the
    verdict. This is what lets a bundle name a policy instead of recording
    ``unspecified``.
    """
    canonical = json.dumps(
        [
            {"id": r.rule_id, "expression": r.expression, "description": r.description}
            for r in rules
        ],
        sort_keys=True,
        separators=(",", ":"),
    )
    return f"sha256:{_sha256(canonical.encode('utf-8'))}"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class BundleManifest(TypedDict):
    """The manifest keys, so a splat into EvidenceBundle type-checks."""

    engine_version: str
    schema_version: str
    weight_profile: str
    policy_version: str
    rubric_version: str
    knowledge_base_version: str


def bundle_manifest(
    weight_profile: str = "",
    policy_version: str = UNSPECIFIED,
) -> BundleManifest:
    """The version manifest recorded on every bundle created from now on."""
    return {
        "engine_version": engine_version(),
        "schema_version": str(BUNDLE_SCHEMA_VERSION),
        "weight_profile": weight_profile,
        "policy_version": policy_version,
        "rubric_version": rubric_version(),
        "knowledge_base_version": knowledge_base_version(),
    }


def derivation_references(
    *,
    weight_profile: str = "",
    policy_rules: Sequence[Any] = (),
    input_id: str = "",
    input_bytes: bytes | None = None,
) -> list[Any]:
    """The derivation list: every input the verdict was derived from.

    One entry per role, so a reader can reconstruct which engine, applied which
    rubric, with which weights, under which policy, to which input
    (docs/ARTIFACT-IDENTITY.md). Ordered by role so two runs over the same
    inputs produce the same list, and therefore the same signed bytes.

    A role whose artifact is unavailable is still emitted, with an empty hash.
    An unresolvable reference is a defect a reader should see rather than one
    the engine should hide by omission.
    """
    from src.core.taxonomy import Reference, ReferenceRole

    commitments = _artifact_commitments()
    refs: list[Reference] = []

    def committed(role: ReferenceRole) -> Reference:
        artifact = commitments.get(role.value)
        if artifact:
            return Reference(
                role=role,
                id=f"{artifact['label']}@sha256:{artifact['sha256']}",
                hash=f"sha256:{artifact['sha256']}",
                location=artifact["location"],
            )
        return Reference(role=role, id="", hash="")

    refs.append(
        Reference(
            role=ReferenceRole.ENGINE,
            id=engine_version(),
            hash=f"sha256:{_sha256(engine_version().encode('utf-8'))}",
        )
    )
    refs.append(
        Reference(
            role=ReferenceRole.SCHEMA,
            id=f"evidence-bundle@v{BUNDLE_SCHEMA_VERSION}",
            hash=f"sha256:{_sha256(f'evidence-bundle/v{BUNDLE_SCHEMA_VERSION}'.encode('utf-8'))}",
        )
    )
    refs.append(
        Reference(
            role=ReferenceRole.WEIGHTS,
            id=weight_profile or "default",
            hash=weights_hash(weight_profile or "default"),
        )
    )
    refs.append(committed(ReferenceRole.RUBRIC))
    refs.append(committed(ReferenceRole.KNOWLEDGE_BASE))

    if policy_rules:
        refs.append(
            Reference(
                role=ReferenceRole.POLICY,
                id=f"policy/{len(policy_rules)} rules",
                hash=policy_hash(policy_rules),
                inline=json.dumps(
                    [
                        {"id": r.rule_id, "expression": r.expression}
                        for r in policy_rules
                    ],
                    sort_keys=True,
                    separators=(",", ":"),
                ),
            )
        )
    else:
        refs.append(Reference(role=ReferenceRole.POLICY, id=UNSPECIFIED, hash=""))

    if input_bytes is not None:
        refs.append(
            Reference(
                role=ReferenceRole.INPUT,
                id=input_id or "attestation",
                hash=f"sha256:{_sha256(input_bytes)}",
            )
        )
    else:
        refs.append(Reference(role=ReferenceRole.INPUT, id=input_id, hash=""))

    return refs
