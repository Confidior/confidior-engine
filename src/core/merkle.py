"""RFC 6962 Merkle tree arithmetic.

The one thing a transparency log's proof is worth checking against is the tree
the log named, and both of the proof formats this engine reads -- Rekor's JSON
inclusion proof and SCITT's COSE receipt (RFC 9942 §5.2) -- use the same hash
tree from RFC 9162 (which obsoleted RFC 6962). Two copies of this arithmetic
would be two chances to disagree, so it lives here once.

The distinction that matters and is easy to lose: this proves an entry is in
*some* tree with a given root. It says nothing about whether the log signed
that root, nor whether the tree is append-only. Those are separate checks.
"""

from __future__ import annotations

import hashlib

#: RFC 9162 §2.1.1: leaves are prefixed with 0x00 before hashing.
LEAF_PREFIX = b"\x00"

#: RFC 9162 §2.1.1: interior nodes are prefixed with 0x01.
NODE_PREFIX = b"\x01"


def leaf_hash(data: bytes) -> bytes:
    """The RFC 9162 leaf hash of ``data``."""
    return hashlib.sha256(LEAF_PREFIX + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    """The RFC 9162 interior node hash of two children."""
    return hashlib.sha256(NODE_PREFIX + left + right).digest()


def root_from_inclusion_proof(
    leaf: bytes, index: int, size: int, audit_path: list[bytes]
) -> bytes | None:
    """Recompute the Merkle root of one leaf from its audit path (RFC 9162 §2.1.3.2).

    Returns ``None`` when the proof is inconsistent with ``index`` and ``size``
    -- an audit path that runs past the root, or an index outside the tree. A
    caller compares the result against the log's stated root hash; ``None``
    means the proof could not be evaluated at all, which is not the same as a
    proof that evaluated to the wrong root.

    ``leaf`` is the already-hashed leaf, not the raw data.
    """
    if size <= 0 or index < 0 or index >= size:
        return None
    fn, sn = index, size - 1
    node = leaf
    for sibling in audit_path:
        if sn == 0:
            return None  # audit path longer than the tree allows
        if fn & 1 or fn == sn:
            node = node_hash(sibling, node)
            while not fn & 1 and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            node = node_hash(node, sibling)
        fn >>= 1
        sn >>= 1
    return node if sn == 0 else None


def verify_inclusion(
    leaf: bytes, index: int, size: int, audit_path: list[bytes], root: bytes
) -> bool:
    """True when ``leaf`` at ``index`` proves into ``root`` at the given size."""
    return root_from_inclusion_proof(leaf, index, size, audit_path) == root
