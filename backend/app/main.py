"""
app/main.py

Async FastAPI server for the zero-knowledge vault.

Every endpoint here only ever touches ciphertext, public keys, signatures,
and metadata. There is no code path anywhere in this file that decrypts
user data — the server has no key material capable of doing so.
"""
from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import AsyncSessionLocal, EncryptedRecord, UserVault, init_models, new_uuid
from app.services.merkle_audit import append_audit_entry, verify_chain_integrity
from app.services.session_and_rate_limit import limiter, issue_session_token
from slowapi.errors import RateLimitExceeded
from slowapi import _rate_limit_exceeded_handler


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_models()
    yield


app = FastAPI(title="Zero-Knowledge Vault API", version="1.0.0", lifespan=lifespan)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


async def get_session() -> AsyncSession:
    async with AsyncSessionLocal() as session:
        yield session


# ---------------------------------------------------------------------------
# Signature verification shim
# ---------------------------------------------------------------------------
# The real ML-DSA-65 / FROST verification math lives client-side (Section 1,
# TypeScript). A production deployment calls out to a small verified native
# binding (e.g. liboqs Python bindings for ML-DSA, or a Python port of the
# ed25519 FROST verify) here. This shim is explicit about that gap rather
# than silently stubbing `return True`, which would be a real vulnerability
# masquerading as a placeholder.
def verify_signature_placeholder(message: bytes, signature: bytes, public_key: bytes) -> bool:
    raise NotImplementedError(
        "Wire this to a real ML-DSA-65 verifier (e.g. python-oqs) or FROST/ed25519 "
        "verifier before deploying. Signature verification must not be stubbed out "
        "in a zero-knowledge system — that would let anyone forge audit entries."
    )


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

class RegisterVaultRequest(BaseModel):
    username: str = Field(min_length=3, max_length=255)
    kdf_salt_b64: str
    x25519_public_key_b64: str
    mlkem768_public_key_b64: str
    mldsa65_public_key_b64: str
    wrapped_master_key_b64: str
    wrapped_master_key_nonce_b64: str


class RegisterVaultResponse(BaseModel):
    vault_id: str


class StoreRecordRequest(BaseModel):
    ciphertext_b64: str
    aes_gcm_nonce_b64: str
    aes_gcm_tag_b64: str
    ratchet_step: int
    fhe_search_tags_b64: Optional[str] = None
    signature_b64: str
    signer_public_key_b64: str


class StoreRecordResponse(BaseModel):
    record_id: str
    merkle_root_b64: str
    sequence_number: int


class SearchEncryptedRequest(BaseModel):
    fhe_search_tags_b64: str  # opaque encrypted query tag — server does blind equality match only


class SearchEncryptedResponse(BaseModel):
    matching_record_ids: list[str]


class ShredRecordRequest(BaseModel):
    signature_b64: str
    signer_public_key_b64: str


class AuditVerifyResponse(BaseModel):
    intact: bool
    violation_count: int
    violations: list[str]


# ---------------------------------------------------------------------------
# Small base64 helpers (keeps request/response bodies JSON-safe)
# ---------------------------------------------------------------------------

import base64


def b64d(s: str) -> bytes:
    return base64.b64decode(s)


def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.post("/api/v1/vault/register", response_model=RegisterVaultResponse, status_code=201)
@limiter.limit("5/hour")
async def register_vault(
    request: Request, req: RegisterVaultRequest, session: AsyncSession = Depends(get_session)
):
    existing = await session.execute(select(UserVault).where(UserVault.username == req.username))
    if existing.scalar_one_or_none() is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "Username already registered.")

    vault = UserVault(
        id=new_uuid(),
        username=req.username,
        kdf_salt=b64d(req.kdf_salt_b64),
        x25519_public_key=b64d(req.x25519_public_key_b64),
        mlkem768_public_key=b64d(req.mlkem768_public_key_b64),
        mldsa65_public_key=b64d(req.mldsa65_public_key_b64),
        wrapped_master_key=b64d(req.wrapped_master_key_b64),
        wrapped_master_key_nonce=b64d(req.wrapped_master_key_nonce_b64),
    )
    session.add(vault)
    await session.commit()
    return RegisterVaultResponse(vault_id=vault.id)


@app.get("/api/v1/vault/{vault_id}/challenge")
async def get_auth_challenge(vault_id: str, session: AsyncSession = Depends(get_session)):
    """
    Returns the vault's KDF salt and public keys so the client can derive
    its master key locally and prove possession via a signed challenge.
    No password, hash, or key material the server holds is ever returned
    because none of it exists here in a usable form.
    """
    vault = await session.get(UserVault, vault_id)
    if vault is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Vault not found.")
    return {
        "kdf_salt_b64": b64e(vault.kdf_salt),
        "kdf_memory_kib": vault.kdf_memory_kib,
        "kdf_iterations": vault.kdf_iterations,
        "kdf_parallelism": vault.kdf_parallelism,
        "mldsa65_public_key_b64": b64e(vault.mldsa65_public_key),
        "webauthn_prf_supported": vault.webauthn_prf_supported,
    }


@app.post("/api/v1/vault/{vault_id}/store", response_model=StoreRecordResponse, status_code=201)
async def store_record(
    vault_id: str, req: StoreRecordRequest, session: AsyncSession = Depends(get_session)
):
    vault = await session.get(UserVault, vault_id)
    if vault is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Vault not found.")

    record = EncryptedRecord(
        id=new_uuid(),
        vault_id=vault_id,
        ciphertext=b64d(req.ciphertext_b64),
        aes_gcm_nonce=b64d(req.aes_gcm_nonce_b64),
        aes_gcm_tag=b64d(req.aes_gcm_tag_b64),
        ratchet_step=req.ratchet_step,
        fhe_search_tags=b64d(req.fhe_search_tags_b64) if req.fhe_search_tags_b64 else None,
    )
    session.add(record)
    await session.flush()

    try:
        audit_result = await append_audit_entry(
            session=session,
            vault_id=vault_id,
            action="record.store",
            record_id=record.id,
            signature=b64d(req.signature_b64),
            signer_public_key=b64d(req.signer_public_key_b64),
            verify_signature_fn=verify_signature_placeholder,
        )
    except NotImplementedError:
        await session.rollback()
        raise HTTPException(
            status.HTTP_501_NOT_IMPLEMENTED,
            "Server signature verification is not wired to a real verifier yet. See main.py.",
        )
    except ValueError as exc:
        await session.rollback()
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc))

    await session.commit()
    return StoreRecordResponse(
        record_id=record.id,
        merkle_root_b64=b64e(audit_result.merkle_root),
        sequence_number=audit_result.sequence_number,
    )


@app.post(
    "/api/v1/vault/{vault_id}/search-encrypted",
    response_model=SearchEncryptedResponse,
)
async def search_encrypted(
    vault_id: str, req: SearchEncryptedRequest, session: AsyncSession = Depends(get_session)
):
    """
    Blind equality match over opaque FHE/blind-index tags. The server
    compares ciphertext bytes for exact match only — it performs no
    decryption and learns nothing about which plaintext values matched
    beyond "these ciphertext tags were byte-equal."
    """
    query_tag = b64d(req.fhe_search_tags_b64)
    result = await session.execute(
        select(EncryptedRecord.id).where(
            EncryptedRecord.vault_id == vault_id,
            EncryptedRecord.fhe_search_tags == query_tag,
            EncryptedRecord.is_shredded.is_(False),
        )
    )
    matching_ids = [row[0] for row in result.all()]
    return SearchEncryptedResponse(matching_record_ids=matching_ids)


@app.delete("/api/v1/vault/{vault_id}/shred/{record_id}", status_code=200)
async def shred_record(
    vault_id: str,
    record_id: str,
    req: ShredRecordRequest,
    session: AsyncSession = Depends(get_session),
):
    """
    Cryptographic shredding: wipes wrapped_key_reference so the ciphertext
    (which may remain on disk pending a physical delete/vacuum) is
    permanently unrecoverable — there is no key left, anywhere, to unwrap it.
    """
    record = await session.get(EncryptedRecord, record_id)
    if record is None or record.vault_id != vault_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Record not found.")

    try:
        await append_audit_entry(
            session=session,
            vault_id=vault_id,
            action="record.shred",
            record_id=record_id,
            signature=b64d(req.signature_b64),
            signer_public_key=b64d(req.signer_public_key_b64),
            verify_signature_fn=verify_signature_placeholder,
        )
    except NotImplementedError:
        await session.rollback()
        raise HTTPException(status.HTTP_501_NOT_IMPLEMENTED, "Signature verification not wired up. See main.py.")
    except ValueError as exc:
        await session.rollback()
        raise HTTPException(status.HTTP_400_BAD_REQUEST, str(exc))

    record.is_shredded = True
    record.wrapped_key_reference = None
    record.ciphertext = b"\x00" * len(record.ciphertext)  # overwrite; a VACUUM/TRIM policy should follow

    await session.commit()
    return {"shredded": True, "record_id": record_id}


@app.get("/api/v1/vault/{vault_id}/audit/verify", response_model=AuditVerifyResponse)
async def verify_audit_trail(vault_id: str, session: AsyncSession = Depends(get_session)):
    violations = await verify_chain_integrity(session, vault_id)
    return AuditVerifyResponse(
        intact=len(violations) == 0,
        violation_count=len(violations),
        violations=[f"seq {v.sequence_number}: {v.reason}" for v in violations],
    )


class RecordSummary(BaseModel):
    record_id: str
    ratchet_step: int
    is_shredded: bool
    created_at: str


class ListRecordsResponse(BaseModel):
    records: list[RecordSummary]
    next_cursor: Optional[str] = None


@app.get("/api/v1/vault/{vault_id}/records", response_model=ListRecordsResponse)
@limiter.limit("60/minute")
async def list_records(
    request: Request,
    vault_id: str,
    cursor: Optional[str] = None,
    limit: int = 25,
    session: AsyncSession = Depends(get_session),
):
    """
    Cursor-paginated listing of a vault's records (metadata only — no
    ciphertext, so this endpoint is cheap and safe to poll). `cursor` is the
    record_id to resume after; results are ordered by ratchet_step so
    pagination is stable even as new records are appended concurrently.
    """
    limit = max(1, min(limit, 100))
    query = select(EncryptedRecord).where(EncryptedRecord.vault_id == vault_id)
    if cursor:
        cursor_record = await session.get(EncryptedRecord, cursor)
        if cursor_record is not None:
            query = query.where(EncryptedRecord.ratchet_step > cursor_record.ratchet_step)
    query = query.order_by(EncryptedRecord.ratchet_step.asc()).limit(limit + 1)

    result = await session.execute(query)
    rows = result.scalars().all()
    has_more = len(rows) > limit
    rows = rows[:limit]

    return ListRecordsResponse(
        records=[
            RecordSummary(
                record_id=r.id,
                ratchet_step=r.ratchet_step,
                is_shredded=r.is_shredded,
                created_at=r.created_at.isoformat(),
            )
            for r in rows
        ],
        next_cursor=rows[-1].id if has_more and rows else None,
    )


@app.post("/api/v1/vault/{vault_id}/session")
async def create_session(vault_id: str, session: AsyncSession = Depends(get_session)):
    """
    Issues a short-lived session JWT once the client has proven possession
    of the vault (in a full implementation, this endpoint sits behind the
    same signature-verified challenge flow as /store and /shred — wire
    verify_signature_placeholder here too before deploying).
    """
    vault = await session.get(UserVault, vault_id)
    if vault is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Vault not found.")
    return {"access_token": issue_session_token(vault_id), "token_type": "bearer", "expires_in_minutes": 15}


@app.get("/health")
async def health():
    return {"status": "ok"}
