"""
app/services/merkle_audit.py

Hash-chained + Merkle-rooted audit log service.

Two integrity properties are combined here, deliberately:

1. HASH CHAIN (tamper-evidence of ORDER): leaf_hash_i commits to
   leaf_hash_{i-1}, so re-ordering or deleting a historical row breaks
   every leaf_hash after it.

2. MERKLE ROOT (tamper-evidence of CONTENT, cheaply verifiable): the root
   after each append is stored alongside the leaf, so a client holding an
   old root can confirm "yes, this specific historical state really was
   the server's state at that time" without re-hashing the entire log —
   they only need the leaves between then and now (a Merkle proof), not
   the full history.

The signature (ML-DSA-65 or FROST-aggregated ed25519, produced client-side
per Section 1) is verified here but never generated here — the server
never holds a signing key for the vault owner.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional, Sequence

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.vault import MerkleAuditLog

GENESIS_HASH = b"\x00" * 32


def sha256(*parts: bytes) -> bytes:
    h = hashlib.sha256()
    for p in parts:
        h.update(p)
    return h.digest()


def compute_leaf_hash(
    previous_leaf_hash: Optional[bytes],
    action: str,
    record_id: Optional[str],
    timestamp: datetime,
) -> bytes:
    prev = previous_leaf_hash or GENESIS_HASH
    payload = json.dumps(
        {
            "action": action,
            "record_id": record_id,
            "timestamp": timestamp.astimezone(timezone.utc).isoformat(),
        },
        sort_keys=True,
    ).encode("utf-8")
    return sha256(prev, payload)


def compute_merkle_root(leaf_hashes: Sequence[bytes]) -> bytes:
    """
    Standard binary Merkle tree root over an ordered list of leaves.
    Odd node at any level is promoted (duplicated) per common convention
    (same approach Bitcoin uses) — documented here so it's not a silent
    surprise if you diff against a different Merkle implementation.
    """
    if not leaf_hashes:
        return GENESIS_HASH
    level = list(leaf_hashes)
    while len(level) > 1:
        next_level = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else level[i]
            next_level.append(sha256(left, right))
        level = next_level
    return level[0]


@dataclass
class AuditAppendResult:
    leaf_hash: bytes
    merkle_root: bytes
    sequence_number: int


async def append_audit_entry(
    session: AsyncSession,
    vault_id: str,
    action: str,
    record_id: Optional[str],
    signature: bytes,
    signer_public_key: bytes,
    verify_signature_fn,
) -> AuditAppendResult:
    """
    Appends a new leaf. `verify_signature_fn(message: bytes, signature: bytes,
    public_key: bytes) -> bool` is injected so this module stays agnostic
    to which signature scheme (ML-DSA-65 vs FROST/ed25519) is in play —
    wire in verify_audit_record from crypto-suite.ts's Python equivalent,
    or verify_threshold_signature's server-side counterpart.
    """
    result = await session.execute(
        select(MerkleAuditLog)
        .where(MerkleAuditLog.vault_id == vault_id)
        .order_by(MerkleAuditLog.sequence_number.desc())
        .limit(1)
    )
    last_entry = result.scalar_one_or_none()

    previous_leaf_hash = last_entry.leaf_hash if last_entry else None
    next_sequence = (last_entry.sequence_number + 1) if last_entry else 0
    timestamp = datetime.now(timezone.utc)

    leaf_hash = compute_leaf_hash(previous_leaf_hash, action, record_id, timestamp)

    if not verify_signature_fn(leaf_hash, signature, signer_public_key):
        raise ValueError("Audit entry signature verification failed — refusing to append unsigned/forged entry.")

    # Recompute the full root by walking existing leaves + the new one.
    # For very large logs, replace this with an incremental Merkle Mountain
    # Range (MMR) structure — flagged rather than silently left O(n).
    existing = await session.execute(
        select(MerkleAuditLog.leaf_hash)
        .where(MerkleAuditLog.vault_id == vault_id)
        .order_by(MerkleAuditLog.sequence_number.asc())
    )
    all_leaf_hashes = [row[0] for row in existing.all()] + [leaf_hash]
    merkle_root = compute_merkle_root(all_leaf_hashes)

    entry = MerkleAuditLog(
        vault_id=vault_id,
        sequence_number=next_sequence,
        action=action,
        record_id=record_id,
        leaf_hash=leaf_hash,
        previous_leaf_hash=previous_leaf_hash,
        merkle_root_at_append=merkle_root,
        signature=signature,
        signer_public_key=signer_public_key,
    )
    session.add(entry)
    await session.flush()

    return AuditAppendResult(leaf_hash=leaf_hash, merkle_root=merkle_root, sequence_number=next_sequence)


@dataclass
class IntegrityViolation:
    sequence_number: int
    reason: str


async def verify_chain_integrity(session: AsyncSession, vault_id: str) -> list[IntegrityViolation]:
    """
    Walks the full chain and re-derives every leaf hash and root from
    scratch, flagging exactly where (if anywhere) tampering occurred.
    Returns an empty list if the chain is fully intact.
    """
    result = await session.execute(
        select(MerkleAuditLog)
        .where(MerkleAuditLog.vault_id == vault_id)
        .order_by(MerkleAuditLog.sequence_number.asc())
    )
    entries = result.scalars().all()

    violations: list[IntegrityViolation] = []
    previous_hash: Optional[bytes] = None
    seen_hashes: list[bytes] = []

    for entry in entries:
        if entry.previous_leaf_hash != previous_hash:
            violations.append(
                IntegrityViolation(
                    entry.sequence_number,
                    "previous_leaf_hash does not match the prior entry's leaf_hash — chain break.",
                )
            )

        recomputed_leaf = compute_leaf_hash(
            entry.previous_leaf_hash, entry.action, entry.record_id, entry.created_at
        )
        if recomputed_leaf != entry.leaf_hash:
            violations.append(
                IntegrityViolation(
                    entry.sequence_number,
                    "Stored leaf_hash does not match recomputed hash of (prev || action || record_id || timestamp) — row was modified after the fact.",
                )
            )

        seen_hashes.append(entry.leaf_hash)
        recomputed_root = compute_merkle_root(seen_hashes)
        if recomputed_root != entry.merkle_root_at_append:
            violations.append(
                IntegrityViolation(
                    entry.sequence_number,
                    "merkle_root_at_append does not match recomputed root over all leaves up to this point.",
                )
            )

        previous_hash = entry.leaf_hash

    return violations
