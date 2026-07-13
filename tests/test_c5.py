from pathlib import Path

from src.ingest.raw.c5 import (
    find_criterion,
    load_all_c5_families,
    load_c5_family,
)

C5_DIR = Path("data/c5/v2026-04-bsi")


def test_load_ops_family():
    family = load_c5_family(C5_DIR / "OPS.yml")
    assert family.family_id == "OPS"
    assert len(family.criteria) > 0


def test_load_all_families():
    families = load_all_c5_families(C5_DIR)
    assert len(families) == 18
    family_ids = {f.family_id for f in families}
    assert "OPS" in family_ids
    assert "CRY" in family_ids
    assert "IAM" in family_ids
    assert "HR" in family_ids
    assert "PS" in family_ids


def test_find_ops_32():
    families = load_all_c5_families(C5_DIR)
    criterion = find_criterion(families, "32")
    assert criterion is not None
    assert criterion.name == "Confidential Computing - Policies and Procedures"
    assert len(criterion.basic) >= 3


def test_find_ops_33():
    families = load_all_c5_families(C5_DIR)
    criterion = find_criterion(families, "33")
    assert criterion is not None
    assert criterion.name == "Confidential Computing - Remote Attestation"
    assert len(criterion.basic) >= 3


def test_ops_32_subcriteria():
    families = load_all_c5_families(C5_DIR)
    criterion = find_criterion(families, "32")
    basic_ids = [s.identifier for s in criterion.basic]
    assert "01B" in basic_ids
    assert "02B" in basic_ids
    assert "03B" in basic_ids


def test_ops_33_subcriteria():
    families = load_all_c5_families(C5_DIR)
    criterion = find_criterion(families, "33")
    basic_ids = [s.identifier for s in criterion.basic]
    assert "01B" in basic_ids
    assert "02B" in basic_ids
    assert "03B" in basic_ids


def test_find_nonexistent_criterion():
    families = load_all_c5_families(C5_DIR)
    assert find_criterion(families, "99") is None


def test_criterion_has_information():
    families = load_all_c5_families(C5_DIR)
    criterion = find_criterion(families, "32")
    assert len(criterion.information) > 0
