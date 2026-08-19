"""Primary-source provenance guard for the attack DB.

Every ``affected_platforms`` tag must be backed by an in-data ``mapping_sources``
entry that cites the primary source (paper/CVE/advisory), a quoted evidence
passage, and a confidence level. This makes each mapping independently
auditable; a reviewer reads the cited source, not a hardcoded table.

What this guards against:
- a platform tag added without a source (silent unverifiable claim)
- a tag removed while its source entry lingers (stale provenance)
- a tag whose evidence is missing or whose confidence is out of the enum

It does NOT independently re-read the papers; it enforces that the evidence
is present and self-consistent so it can be reviewed.
"""
from src.core.attacks import TEE_ATTACKS

VALID_CONFIDENCE = {"confirmed", "inferred", "unconfirmed"}
# Platforms that have no taxonomy enum but can be named as the attack's real
# target in mapping_sources["INTENT"]["targets"]. For now we only require the
# INTENT key itself; free-form target strings are allowed.
ALLOWED_KEYS = {
    "Intel-TDX", "AMD-SEV-SNP", "AWS-Nitro", "NVIDIA-GPU-CC",
    "Apple-PCC", "ARM-CCA", "IBM-Secure-Execution", "Hygon-CSV",
    "RISC-V-CoVE", "INTENT",
}


def _platform_value(p) -> str:
    return p.value if hasattr(p, "value") else str(p)


def test_every_platform_tag_has_mapping_source():
    """Each non-empty affected_platforms tag must cite a primary source."""
    for attack in TEE_ATTACKS:
        ms = attack.mapping_sources if hasattr(attack, "mapping_sources") else None
        for p in attack.affected_platforms:
            key = _platform_value(p)
            assert ms, (
                f"{attack.name}: no mapping_sources, but affected_platforms includes {key}"
            )
            assert key in ms, (
                f"{attack.name}: affected_platforms includes {key} but mapping_sources "
                f"has no '{key}' entry. Add the primary source."
            )
            entry = ms[key]
            assert entry.get("source_url"), f"{attack.name}: {key} missing source_url"
            assert entry.get("evidence"), f"{attack.name}: {key} missing evidence quote"
            assert entry.get("confidence") in VALID_CONFIDENCE, (
                f"{attack.name}: {key} confidence must be one of {sorted(VALID_CONFIDENCE)}"
            )


def test_mapping_sources_keys_match_platform_tags():
    """A mapping_sources platform entry with no matching affected_platforms tag is stale."""
    for attack in TEE_ATTACKS:
        ms = attack.mapping_sources if hasattr(attack, "mapping_sources") else None
        if not ms:
            continue
        tagged = {_platform_value(p) for p in attack.affected_platforms}
        for key in ms:
            assert key in tagged or key == "INTENT", (
                f"{attack.name}: mapping_sources has '{key}' but affected_platforms does not "
                f"include it (stale provenance). Remove or re-add the tag."
            )


def test_empty_platform_attacks_have_intent_or_no_mapping():
    """Attacks with no affected_platforms should either declare their real target
    via INTENT, or have no mapping_sources (truly unknown)."""
    for attack in TEE_ATTACKS:
        ms = getattr(attack, "mapping_sources", None) or {}
        if not attack.affected_platforms and ms:
            assert "INTENT" in ms, (
                f"{attack.name}: no affected_platforms but mapping_sources present without "
                f"INTENT. Add INTENT explaining what this attack actually targets."
            )
            entry = ms["INTENT"]
            assert _entry_valid(entry), (
                f"{attack.name}: INTENT entry must have source_url, evidence, and confidence."
            )


def _entry_valid(entry) -> bool:
    return bool(
        entry.get("source_url")
        and entry.get("evidence")
        and entry.get("confidence") in VALID_CONFIDENCE
    )


def test_all_mapping_sources_have_valid_schema():
    """Every mapping_sources entry has the required shape."""
    for attack in TEE_ATTACKS:
        ms = attack.mapping_sources if hasattr(attack, "mapping_sources") else None
        if not ms:
            continue
        for key, entry in ms.items():
            assert key in ALLOWED_KEYS, f"{attack.name}: unknown mapping_sources key '{key}'"
            assert isinstance(entry, dict), f"{attack.name}: {key} must be an object"
            assert _entry_valid(entry), (
                f"{attack.name}: {key} must have source_url, evidence, confidence"
            )
