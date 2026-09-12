"""
app/models/vault.py

Core zero-knowledge database models.

Hard invariant enforced by convention throughout this file: every column
that could conceivably hold user plaintext is typed as LargeBinary/Text and
documented as "ciphertext" or "public key material" — never a plaintext
column exists for vault contents. The server's job is to store and index
opaque bytes; it never has the keys needed to open them.
"""
from __future__ import annotations

from typing import Optional

from sqlalchemy import (
    BigInteger,
    Boolean,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin, new_uuid


class UserVault(TimestampMixin, Base):
    """
    One row per user vault. Holds only public key material, salts, and
    WRAPPED (still-encrypted) key blobs — never a raw master key.
    """

    __tablename__ = "user_vaults"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    username: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)

    # Argon2id parameters + salt (public by design — salts are not secret).
    kdf_salt: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    kdf_memory_kib: Mapped[int] = mapped_column(Integer, nullable=False, default=65536)
    kdf_iterations: Mapped[int] = mapped_column(Integer, nullable=False, default=3)
    kdf_parallelism: Mapped[int] = mapped_column(Integer, nullable=False, default=4)

    # Hybrid PQC public keys (Section 1). Private keys never leave the client.
    x25519_public_key: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    mlkem768_public_key: Mapped[bytes] = mapped_column(LargeBinary(1184), nullable=False)
    mldsa65_public_key: Mapped[bytes] = mapped_column(LargeBinary(1952), nullable=False)

    # The vault master key, wrapped (encrypted) under the Argon2id/PRF-derived
    # key. This ciphertext is useless to the server without that derived key.
    wrapped_master_key: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    wrapped_master_key_nonce: Mapped[bytes] = mapped_column(LargeBinary(12), nullable=False)

    # WebAuthn credential metadata (public key + credential ID; no secrets).
    webauthn_credential_id: Mapped[Optional[bytes]] = mapped_column(LargeBinary, nullable=True)
    webauthn_public_key: Mapped[Optional[bytes]] = mapped_column(LargeBinary, nullable=True)
    webauthn_sign_count: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    webauthn_prf_supported: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # Lockout / VDF state (Section 1 vdf.ts) — tracks failed attempts only,
    # never key material.
    failed_unlock_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    current_lockout_vdf_steps: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)

    records: Mapped[list["EncryptedRecord"]] = relationship(
        back_populates="vault", cascade="all, delete-orphan"
    )
    audit_logs: Mapped[list["MerkleAuditLog"]] = relationship(
        back_populates="vault", cascade="all, delete-orphan"
    )
    guardian_shares: Mapped[list["GuardianShare"]] = relationship(
        back_populates="vault", cascade="all, delete-orphan"
    )
    counters: Mapped[list["HomomorphicCounter"]] = relationship(
        back_populates="vault", cascade="all, delete-orphan"
    )

    __table_args__ = (Index("ix_user_vaults_username_lower", "username"),)


class EncryptedRecord(TimestampMixin, Base):
    """
    One encrypted payload (a "document", "note", "credential", etc. in the
    user's vault). All content columns are ciphertext or FHE-searchable
    tags — never plaintext, never a plaintext field name or title.
    """

    __tablename__ = "encrypted_records"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    vault_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("user_vaults.id", ondelete="CASCADE"), nullable=False, index=True
    )

    ciphertext: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    aes_gcm_nonce: Mapped[bytes] = mapped_column(LargeBinary(12), nullable=False)
    aes_gcm_tag: Mapped[bytes] = mapped_column(LargeBinary(16), nullable=False)

    # Ratchet position (Section 1 ratchet.ts) this record's key was derived
    # at. Public metadata only — the actual per-record key is never stored.
    ratchet_step: Mapped[int] = mapped_column(BigInteger, nullable=False)

    # Opaque FHE-searchable index tags (CKKS ciphertexts / deterministic
    # blind-index tokens) — enables equality/range search over encrypted
    # content per Section 3, without the server learning the plaintext tag.
    fhe_search_tags: Mapped[Optional[bytes]] = mapped_column(LargeBinary, nullable=True)

    # Cryptographic shredding: when true, wrapped_key_reference has been
    # wiped and this ciphertext is permanently unrecoverable even though
    # the row (or its ciphertext blob) may still physically exist on disk.
    is_shredded: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    wrapped_key_reference: Mapped[Optional[bytes]] = mapped_column(LargeBinary, nullable=True)

    vault: Mapped["UserVault"] = relationship(back_populates="records")

    __table_args__ = (
        Index("ix_encrypted_records_vault_ratchet", "vault_id", "ratchet_step"),
        Index("ix_encrypted_records_fhe_tags", "fhe_search_tags"),
    )


class MerkleAuditLog(TimestampMixin, Base):
    """
    Append-only, hash-chained audit ledger. Every mutation to a vault
    appends exactly one leaf. Each leaf commits to the previous leaf's hash,
    so tampering with any historical row breaks the chain from that point
    forward — detectable via verify_chain_integrity() at the service layer.
    """

    __tablename__ = "merkle_audit_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    vault_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("user_vaults.id", ondelete="CASCADE"), nullable=False, index=True
    )

    # Monotonic per-vault sequence number — the leaf's position in the tree.
    sequence_number: Mapped[int] = mapped_column(BigInteger, nullable=False)

    action: Mapped[str] = mapped_column(String(64), nullable=False)  # e.g. "record.store", "record.shred"
    record_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)

    # SHA-256 hash of (previous_leaf_hash || action || record_id || timestamp).
    leaf_hash: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)
    previous_leaf_hash: Mapped[Optional[bytes]] = mapped_column(LargeBinary(32), nullable=True)

    # Root hash of the Merkle tree AFTER this leaf was appended, so any
    # historical root can be re-derived and compared without recomputing
    # the whole tree from scratch.
    merkle_root_at_append: Mapped[bytes] = mapped_column(LargeBinary(32), nullable=False)

    # ML-DSA-65 signature over leaf_hash (Section 1), or an aggregated FROST
    # threshold signature (threshold-signing.ts) if the vault has guardians
    # configured. signer_public_key disambiguates which scheme was used by
    # its byte length (1952 = ML-DSA-65, 32 = ed25519/FROST group key).
    signature: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    signer_public_key: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)

    vault: Mapped["UserVault"] = relationship(back_populates="audit_logs")

    __table_args__ = (
        UniqueConstraint("vault_id", "sequence_number", name="uq_audit_vault_sequence"),
        Index("ix_audit_vault_sequence", "vault_id", "sequence_number"),
    )


class GuardianShare(TimestampMixin, Base):
    """
    Metadata for a social-recovery guardian (Section 1: Shamir + did-recovery.ts).
    The server stores only the guardian's DID and the ENCRYPTED Shamir share
    blob (encrypted to the guardian's own DID public key) — it cannot
    reconstruct the secret from this table alone, and doesn't need to.
    """

    __tablename__ = "guardian_shares"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    vault_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("user_vaults.id", ondelete="CASCADE"), nullable=False, index=True
    )

    guardian_did: Mapped[str] = mapped_column(String(512), nullable=False)
    share_index: Mapped[int] = mapped_column(Integer, nullable=False)  # 1..n, matches Shamir share index
    threshold: Mapped[int] = mapped_column(Integer, nullable=False)  # t, same across all shares for a vault

    # The Shamir share itself, encrypted client-side to guardian_did's public
    # key before upload. Server relays it; it cannot read it.
    encrypted_share_blob: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)

    revoked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    vault: Mapped["UserVault"] = relationship(back_populates="guardian_shares")

    __table_args__ = (
        UniqueConstraint("vault_id", "share_index", name="uq_guardian_vault_share_index"),
    )


class RecoveryAttempt(TimestampMixin, Base):
    """
    Tracks in-progress recovery flows: which Verifiable Credentials
    (did-recovery.ts) have been submitted so far toward the threshold.
    """

    __tablename__ = "recovery_attempts"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    vault_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("user_vaults.id", ondelete="CASCADE"), nullable=False, index=True
    )
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")  # pending|completed|expired

    # Serialized Verifiable Credential JSON documents submitted so far.
    submitted_credentials: Mapped[str] = mapped_column(Text, nullable=False, default="[]")


class HomomorphicCounter(TimestampMixin, Base):
    """
    Server-maintained Paillier-encrypted counter (homomorphic-counters.ts).
    The server can homomorphically add encrypted deltas to `ciphertext_value`
    but has no private key and therefore cannot read the running total.
    """

    __tablename__ = "homomorphic_counters"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    vault_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("user_vaults.id", ondelete="CASCADE"), nullable=False, index=True
    )
    counter_name: Mapped[str] = mapped_column(String(64), nullable=False)  # e.g. "records_stored", "searches_run"

    # Paillier ciphertext, stored as decimal-string bigint (Postgres numeric
    # would truncate at high precision; text preserves exactness).
    ciphertext_value: Mapped[str] = mapped_column(Text, nullable=False)
    paillier_n: Mapped[str] = mapped_column(Text, nullable=False)  # public modulus, decimal string

    vault: Mapped["UserVault"] = relationship(back_populates="counters")

    __table_args__ = (UniqueConstraint("vault_id", "counter_name", name="uq_counter_vault_name"),)
