#!/usr/bin/env python3
"""Publish the commitments for the rubric and the attack knowledge base.

Stage 1 of the ZK path (docs/ZK-ATTESTED-CLAIMS.md). A bundle will name the
rubric and knowledge base it used; this script publishes the hashes of those
inputs so a third party can re-run the engine against exactly the inputs the
bundle names.

Two commitments are published:

  * rubric          -- docs/GRADING.md, content hash
  * knowledge_base  -- data/attacks/, hashed over the sorted list of
                       (relative path, file sha256) pairs

The output file carries no timestamp: it is a pure function of the tree it
describes, which is what makes --check meaningful.

Usage:
    python scripts/publish_commitments.py            # write commitments.json
    python scripts/publish_commitments.py --check    # exit 1 on drift (CI)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

COMMITMENTS_SCHEMA = 1
RUBRIC_PATH = "docs/GRADING.md"
KNOWLEDGE_BASE_PATH = "data/attacks"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def hash_directory(directory: Path) -> tuple[str, int]:
    """Hash a directory as its sorted (relative path, file sha256) pairs."""
    if not directory.is_dir():
        raise FileNotFoundError(f"directory not found: {directory}")

    files = sorted(
        p for p in directory.rglob("*")
        if p.is_file() and not p.name.startswith(".") and "__pycache__" not in p.parts
    )
    digest = hashlib.sha256()
    for path in files:
        digest.update(path.relative_to(directory).as_posix().encode("utf-8"))
        digest.update(b"\x00")
        digest.update(sha256_file(path).encode("utf-8"))
        digest.update(b"\n")
    return digest.hexdigest(), len(files)


def build_commitments(root: Path) -> dict:
    rubric = root / RUBRIC_PATH
    if not rubric.is_file():
        raise FileNotFoundError(f"rubric not found: {rubric}")

    knowledge_base_hash, file_count = hash_directory(root / KNOWLEDGE_BASE_PATH)
    return {
        "schema": COMMITMENTS_SCHEMA,
        "artifacts": [
            {"role": "rubric", "label": RUBRIC_PATH, "sha256": sha256_file(rubric)},
            {
                "role": "knowledge_base",
                "label": KNOWLEDGE_BASE_PATH,
                "sha256": knowledge_base_hash,
                "file_count": file_count,
            },
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help="engine root (default: the parent of this script's directory)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="output path (default: <root>/commitments.json)",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="compare against the committed file instead of writing it",
    )
    args = parser.parse_args()

    root = args.root.resolve()
    output = args.output.resolve() if args.output else root / "commitments.json"

    try:
        commitments = build_commitments(root)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    rendered = json.dumps(commitments, indent=2, sort_keys=True) + "\n"

    if args.check:
        if not output.is_file():
            print(f"error: {output} does not exist; run without --check", file=sys.stderr)
            return 2
        if output.read_text() != rendered:
            print(
                f"drift: {output} does not match the current tree.\n"
                "Re-run without --check and commit the result.",
                file=sys.stderr,
            )
            return 1
        print(f"ok: {output.name} matches the current tree")
        return 0

    output.write_text(rendered)
    for artifact in commitments["artifacts"]:
        count = f" ({artifact['file_count']} files)" if "file_count" in artifact else ""
        print(f"{artifact['role']}: {artifact['label']}{count} sha256:{artifact['sha256']}")
    print(f"wrote {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
