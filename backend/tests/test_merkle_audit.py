"""
tests/test_merkle_audit.py

Verifies: tamper detection, chain integrity, and Merkle root correctness.
Signature verification is mocked here since the real verifier is a
client-side/native binding concern (see main.py's documented gap).
"""
import pytest
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker

from app.models.base import Base
from app.models.vault import UserVault, MerkleAuditLog
from app.services.merkle_audit import append_audit_entry, verify_chain_integrity, compute_merkle_root


def always_valid_signature(message: bytes, signature: bytes, public_key: bytes) -> bool:
    return True


@pytest.fixture
async def session():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    Session = async_sessionmaker(engine, expire_on_commit=False)
    async with Session() as s:
        vault = UserVault(
            id="vault-1",
            username="testuser",
            kdf_salt=b"0" * 32,
            x25519_public_key=b"0" * 32,
            mlkem768_public_key=b"0" * 1184,
            mldsa65_public_key=b"0" * 1952,
            wrapped_master_key=b"ciphertext",
            wrapped_master_key_nonce=b"0" * 12,
        )
        s.add(vault)
        await s.commit()
        yield s
    await engine.dispose()


@pytest.mark.asyncio
async def test_append_and_verify_intact_chain(session):
    for i in range(5):
        await append_audit_entry(
            session, "vault-1", "record.store", f"rec-{i}", b"sig", b"pubkey", always_valid_signature
        )
    await session.commit()

    violations = await verify_chain_integrity(session, "vault-1")
    assert violations == []


@pytest.mark.asyncio
async def test_tamper_detection_on_leaf_hash(session):
    await append_audit_entry(session, "vault-1", "record.store", "rec-0", b"sig", b"pubkey", always_valid_signature)
    await append_audit_entry(session, "vault-1", "record.store", "rec-1", b"sig", b"pubkey", always_valid_signature)
    await session.commit()

    from sqlalchemy import select

    result = await session.execute(select(MerkleAuditLog).order_by(MerkleAuditLog.sequence_number))
    entries = result.scalars().all()
    entries[0].action = "record.store.TAMPERED"
    await session.commit()

    violations = await verify_chain_integrity(session, "vault-1")
    assert len(violations) > 0
    assert any("Stored leaf_hash does not match" in v.reason for v in violations)


@pytest.mark.asyncio
async def test_rejects_forged_signature(session):
    def always_invalid(message, signature, public_key):
        return False

    with pytest.raises(ValueError, match="signature verification failed"):
        await append_audit_entry(
            session, "vault-1", "record.store", "rec-0", b"bad-sig", b"pubkey", always_invalid
        )


def test_merkle_root_deterministic_and_order_sensitive():
    leaves_a = [b"a" * 32, b"b" * 32, b"c" * 32]
    leaves_b = [b"b" * 32, b"a" * 32, b"c" * 32]
    root_a = compute_merkle_root(leaves_a)
    root_b = compute_merkle_root(leaves_b)
    assert root_a != root_b  # order matters
    assert compute_merkle_root(leaves_a) == root_a  # deterministic
