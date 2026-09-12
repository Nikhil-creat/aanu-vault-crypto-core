# AANU Vault

A quantum-resistant, zero-knowledge personal data vault: hybrid post-quantum
encryption, hardware-backed unlock, Merkle-audited storage, and social
recovery — designed so the server never has the technical capability to
read your data.

## What's actually implemented here (read this before demoing it)

Every primitive below uses an audited, real library — nothing here
reimplements core crypto math by hand except where noted, and every "future
tech" claim in this README is scoped to what the code actually does.

| Layer | What it does | Library / standard |
|---|---|---|
| Hybrid KEM | X25519 + ML-KEM-768 combined via HKDF | `@noble/curves`, `@noble/post-quantum` (NIST FIPS 203) |
| Signatures | ML-DSA-65 audit signing | `@noble/post-quantum` (NIST FIPS 204) |
| Threshold signing | FROST 2-round threshold Schnorr (t-of-n) | `@noble/curves` (ed25519 — see caveat below) |
| Key derivation | Argon2id, 64 MiB / t=3 / p=4 | `hash-wasm` |
| Symmetric cipher | AES-256-GCM, random 96-bit nonce per record | WebCrypto |
| Hardware unlock | WebAuthn PRF extension, HKDF-hardened output | WebAuthn spec |
| Social recovery | Shamir 3-of-5 + DID/Verifiable Credentials | `shamirs-secret-sharing`, W3C `did:key` + VC Data Model |
| Forward secrecy | Symmetric KDF-chain ratchet, one-time record keys | HKDF-SHA256 |
| Encrypted counters | Paillier partial homomorphic encryption | Custom bigint implementation (real Paillier, not FHE) |
| Rate limiting | Wesolowski Verifiable Delay Function | Custom bigint implementation |
| Anomaly signals | Statistical heuristics (impossible-travel, hour z-score, etc.) | Client-side, explainable — **not** a trained ML model |
| Audit ledger | Hash-chained + Merkle-rooted, tamper-localizing | SHA-256, custom |
| Server | Async FastAPI + SQLAlchemy 2.0, zero-plaintext schema | FastAPI, asyncpg |

### Known gaps — do not deploy without addressing these

1. **Server-side signature verification is a documented stub** (`app/main.py:verify_signature_placeholder`).
   It intentionally raises `NotImplementedError` rather than silently
   returning `True`. Wire it to a real ML-DSA-65 verifier (e.g. `liboqs`
   Python bindings) or the FROST/ed25519 verify path before this touches
   real user data.
2. **Threshold signing is ed25519, not post-quantum.** There is no mature
   audited threshold scheme for ML-DSA yet. If quantum-resistance of the
   *audit signature itself* matters for your threat model, co-sign with a
   single-device ML-DSA-65 signature as well.
3. **The VDF's RSA modulus must come from a trusted setup** (or a public
   modulus with provably unknown factorization) — never generate it
   yourself in production.
4. **FHE search / TEE enclave execution** (OpenFHE/CKKS, AWS Nitro/SGX)
   are architected for in the schema (`fhe_search_tags` columns, blind
   equality matching in `/search-encrypted`) but the CKKS index itself and
   enclave deployment are infrastructure work beyond a single codebase —
   see `docs/section3-notes.md` if you build this out further.

## Repository layout

```
backend/            Async FastAPI server + SQLAlchemy models + Merkle audit service
  app/main.py        API endpoints (register, store, search-encrypted, shred, audit/verify)
  app/models/        UserVault, EncryptedRecord, MerkleAuditLog, GuardianShare, HomomorphicCounter
  app/services/      Merkle chain construction + tamper detection
  tests/             pytest suite for audit chain integrity
frontend-crypto/    Client-side TypeScript crypto suite (never runs on the server)
  src/crypto-suite.ts       Hybrid KEM, Argon2id, AES-GCM, WebAuthn PRF, Shamir
  src/ratchet.ts            Per-record forward-secrecy key ratchet
  src/homomorphic-counters.ts   Paillier encrypted counters
  src/vdf.ts                Verifiable Delay Function rate-limiting
  src/threshold-signing.ts  FROST threshold Schnorr signing
  src/did-recovery.ts       DID/Verifiable Credential guardian recovery
  src/anomaly-detection.ts  Client-side access-pattern heuristics
docs/index.html     Static project landing page (GitHub Pages ready)
```

## Running it

**Backend:**
```bash
cd backend
pip install -r requirements.txt
uvicorn app.main:app --reload
# API docs at http://localhost:8000/docs
```

**Frontend crypto suite:**
```bash
cd frontend-crypto
npm install
npm run build
npm test
```

**Backend tests:**
```bash
cd backend
pytest
```

## Deploying the live landing page (GitHub Pages)

1. Push this repo to GitHub.
2. Repo Settings → Pages → Source: **Deploy from branch**, branch `main`, folder `/docs`.
3. Your live page appears at `https://<username>.github.io/<repo-name>/` within a few minutes.

## Deploying the API (Render, free tier)

1. Create a new **Web Service** on Render, point it at this repo, root directory `backend`.
2. Build command: `pip install -r requirements.txt`
3. Start command: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
4. Add a managed Postgres instance and set `DATABASE_URL` accordingly (update `app/models/base.py` to read it from the environment rather than the hardcoded string before doing this).

## License

MIT — see `LICENSE`.

## 👤 Author

**NIKHIL CHARY SRIRAMOJU**
- GitHub: [@Nikhil-creat](https://github.com/Nikhil-creat)
- LinkedIn: [nikhil-chary-sriramoju](https://in.linkedin.com/in/nikhil-chary-sriramoju-95041b38a)
- Instagram: [@nikhil__sriramoju](https://www.instagram.com/nikhil__sriramoju?stkn=MTFxdDZobmJtb2RoaA==)
