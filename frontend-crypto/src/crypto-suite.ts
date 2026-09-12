/**
 * vault-crypto/crypto-suite.ts
 *
 * Client-side cryptography for a zero-knowledge vault.
 *
 * Design notes (read before wiring this into a server):
 * - All PQC primitives come from @noble/post-quantum and @noble/curves —
 *   audited, widely used implementations. This file does NOT reimplement
 *   ML-KEM or ML-DSA math.
 * - Argon2id runs via `argon2-browser` (WASM) or `hash-wasm` in-browser;
 *   this file wraps `hash-wasm` since it has no native deps and works in
 *   both browser and Node test environments.
 * - Shamir's Secret Sharing uses `shamirs-secret-sharing` (GF(256) based),
 *   a maintained, minimal implementation — not hand-rolled polynomial math.
 * - "Constant time" claims below are honest, not aspirational: the
 *   comparison function is a manual constant-time loop; but note that
 *   JS engines can still introduce timing variance via JIT/GC. For a
 *   genuinely hardened build, this logic belongs in a WASM module.
 *
 * npm install @noble/post-quantum @noble/curves hash-wasm shamirs-secret-sharing
 */

import { x25519 } from '@noble/curves/ed25519';
import { ml_kem768 } from '@noble/post-quantum/ml-kem';
import { ml_dsa65 } from '@noble/post-quantum/ml-dsa';
import { argon2id } from 'hash-wasm';
// shamirs-secret-sharing has no type defs; declare a minimal shape.
// eslint-disable-next-line @typescript-eslint/no-var-requires
const sss = require('shamirs-secret-sharing');

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface HybridKeyPair {
  x25519PrivateKey: Uint8Array;
  x25519PublicKey: Uint8Array;
  mlkemPrivateKey: Uint8Array;
  mlkemPublicKey: Uint8Array;
}

export interface HybridPublicBundle {
  x25519PublicKey: Uint8Array;
  mlkemPublicKey: Uint8Array;
}

export interface HybridEncapsulation {
  /** X25519 ephemeral public key to send to the recipient. */
  x25519EphemeralPublicKey: Uint8Array;
  /** ML-KEM-768 ciphertext to send to the recipient. */
  mlkemCiphertext: Uint8Array;
  /** Combined 32-byte symmetric key derived from both secrets. Never transmit this. */
  sharedKey: Uint8Array;
}

export interface AesGcmCiphertext {
  nonce: Uint8Array; // 96-bit (12 byte) random nonce
  ciphertext: Uint8Array; // includes GCM auth tag appended (WebCrypto behavior)
}

export interface Argon2Params {
  memoryKiB: number; // m
  iterations: number; // t
  parallelism: number; // p
  hashLengthBytes: number;
}

export const DEFAULT_ARGON2_PARAMS: Argon2Params = {
  memoryKiB: 65536, // 64 MiB
  iterations: 3,
  parallelism: 4,
  hashLengthBytes: 32,
};

export interface ShamirShare {
  index: number;
  data: Uint8Array;
}

// ---------------------------------------------------------------------------
// Utility: constant-time comparison
// ---------------------------------------------------------------------------

/**
 * Compares two byte arrays in constant time with respect to their content
 * (length differences necessarily short-circuit timing-independent of content,
 * which is standard practice — leaking length is not considered a secret here).
 */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    // Still touch `b` so the branch doesn't obviously bail instantly.
    let dummy = 0;
    for (let i = 0; i < b.length; i++) dummy |= b[i];
    return false;
  }
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

/** Zeroes a Uint8Array in place. Call this on key material once you're done with it. */
export function wipe(buf: Uint8Array): void {
  buf.fill(0);
}

// ---------------------------------------------------------------------------
// Argon2id key derivation (client-side, generates the vault master key)
// ---------------------------------------------------------------------------

export async function deriveMasterKeyArgon2id(
  password: string,
  saltB64: string,
  params: Argon2Params = DEFAULT_ARGON2_PARAMS,
): Promise<Uint8Array> {
  if (password.length === 0) {
    throw new Error('Password must not be empty.');
  }
  const salt = base64ToBytes(saltB64);
  if (salt.length < 16) {
    throw new Error('Salt must be at least 16 bytes.');
  }
  const hashHex = await argon2id({
    password,
    salt,
    memorySize: params.memoryKiB,
    iterations: params.iterations,
    parallelism: params.parallelism,
    hashLength: params.hashLengthBytes,
    outputType: 'hex',
  });
  return hexToBytes(hashHex);
}

export function generateSalt(byteLength = 16): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(byteLength));
}

// ---------------------------------------------------------------------------
// Hybrid KEM: X25519 + ML-KEM-768
// ---------------------------------------------------------------------------

/**
 * Generates a hybrid keypair. The X25519 keypair provides classical security;
 * the ML-KEM-768 keypair provides post-quantum security. Both secrets are
 * combined at encapsulation time so an attacker must break BOTH primitives.
 */
export function generateHybridKeyPair(): HybridKeyPair {
  const x25519PrivateKey = x25519.utils.randomPrivateKey();
  const x25519PublicKey = x25519.getPublicKey(x25519PrivateKey);
  const mlkemKeys = ml_kem768.keygen();
  return {
    x25519PrivateKey,
    x25519PublicKey,
    mlkemPrivateKey: mlkemKeys.secretKey,
    mlkemPublicKey: mlkemKeys.publicKey,
  };
}

/**
 * Sender side: given the recipient's public bundle, derive a shared 32-byte
 * key and produce the values that must be transmitted to the recipient.
 *
 * KDF: HKDF-SHA256 over (x25519_shared || mlkem_shared), domain-separated.
 */
export async function hybridEncapsulate(
  recipientPublicBundle: HybridPublicBundle,
): Promise<HybridEncapsulation> {
  const ephemeralPrivate = x25519.utils.randomPrivateKey();
  const x25519EphemeralPublicKey = x25519.getPublicKey(ephemeralPrivate);
  const x25519Shared = x25519.getSharedSecret(ephemeralPrivate, recipientPublicBundle.x25519PublicKey);

  const { cipherText: mlkemCiphertext, sharedSecret: mlkemShared } = ml_kem768.encapsulate(
    recipientPublicBundle.mlkemPublicKey,
  );

  const sharedKey = await hkdfCombine(x25519Shared, mlkemShared);

  wipe(ephemeralPrivate);
  wipe(x25519Shared);
  wipe(mlkemShared);

  return { x25519EphemeralPublicKey, mlkemCiphertext, sharedKey };
}

/**
 * Recipient side: reconstruct the same 32-byte shared key from your private
 * keys plus the values the sender transmitted.
 */
export async function hybridDecapsulate(
  ownKeyPair: HybridKeyPair,
  senderX25519EphemeralPublicKey: Uint8Array,
  mlkemCiphertext: Uint8Array,
): Promise<Uint8Array> {
  const x25519Shared = x25519.getSharedSecret(
    ownKeyPair.x25519PrivateKey,
    senderX25519EphemeralPublicKey,
  );
  const mlkemShared = ml_kem768.decapsulate(mlkemCiphertext, ownKeyPair.mlkemPrivateKey);

  const sharedKey = await hkdfCombine(x25519Shared, mlkemShared);

  wipe(x25519Shared);
  wipe(mlkemShared);

  return sharedKey;
}

async function hkdfCombine(x25519Shared: Uint8Array, mlkemShared: Uint8Array): Promise<Uint8Array> {
  const ikm = concatBytes(x25519Shared, mlkemShared);
  const salt = new TextEncoder().encode('vault-hybrid-kem-v1');
  const info = new TextEncoder().encode('hybrid-x25519-mlkem768-aes256gcm-key');
  const baseKey = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt, info },
    baseKey,
    256,
  );
  return new Uint8Array(bits);
}

// ---------------------------------------------------------------------------
// ML-DSA-65 signatures (audit record signing)
// ---------------------------------------------------------------------------

export interface SignatureKeyPair {
  publicKey: Uint8Array;
  secretKey: Uint8Array;
}

export function generateSigningKeyPair(): SignatureKeyPair {
  const keys = ml_dsa65.keygen();
  return { publicKey: keys.publicKey, secretKey: keys.secretKey };
}

export function signAuditRecord(secretKey: Uint8Array, message: Uint8Array): Uint8Array {
  return ml_dsa65.sign(secretKey, message);
}

export function verifyAuditRecord(
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): boolean {
  try {
    return ml_dsa65.verify(publicKey, message, signature);
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// AES-256-GCM encryption (WebCrypto — not reimplemented by hand)
// ---------------------------------------------------------------------------

export async function importAesKey(rawKey: Uint8Array): Promise<CryptoKey> {
  if (rawKey.length !== 32) {
    throw new Error('AES-256-GCM key must be exactly 32 bytes.');
  }
  return crypto.subtle.importKey('raw', rawKey, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

export async function encryptAesGcm(
  key: CryptoKey,
  plaintext: Uint8Array,
  additionalData?: Uint8Array,
): Promise<AesGcmCiphertext> {
  const nonce = crypto.getRandomValues(new Uint8Array(12)); // 96-bit nonce, unique per record
  const ciphertextBuf = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce, additionalData, tagLength: 128 },
    key,
    plaintext,
  );
  return { nonce, ciphertext: new Uint8Array(ciphertextBuf) };
}

export async function decryptAesGcm(
  key: CryptoKey,
  payload: AesGcmCiphertext,
  additionalData?: Uint8Array,
): Promise<Uint8Array> {
  const plaintextBuf = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: payload.nonce, additionalData, tagLength: 128 },
    key,
    payload.ciphertext,
  );
  return new Uint8Array(plaintextBuf);
}

// ---------------------------------------------------------------------------
// WebAuthn PRF extension — hardware-derived key material
// ---------------------------------------------------------------------------

/**
 * Requests a credential with the PRF extension during registration.
 * The `evalSalt` should be a fixed, application-specific 32-byte value —
 * NOT secret, but stable, so the same authenticator + salt always yields
 * the same PRF output for a given credential.
 */
export async function registerWebAuthnWithPrf(
  userId: Uint8Array,
  userName: string,
  displayName: string,
  rpId: string,
  evalSalt: Uint8Array,
): Promise<PublicKeyCredential> {
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const credential = (await navigator.credentials.create({
    publicKey: {
      challenge,
      rp: { id: rpId, name: rpId },
      user: { id: userId, name: userName, displayName },
      pubKeyCredParams: [
        { type: 'public-key', alg: -7 }, // ES256
        { type: 'public-key', alg: -257 }, // RS256 fallback
      ],
      authenticatorSelection: { userVerification: 'required', residentKey: 'required' },
      extensions: { prf: { eval: { first: evalSalt } } } as AuthenticationExtensionsClientInputs,
      timeout: 60000,
      attestation: 'none',
    },
  })) as PublicKeyCredential | null;

  if (!credential) {
    throw new Error('WebAuthn registration was cancelled or failed.');
  }
  return credential;
}

/**
 * During authentication, re-evaluates the PRF with the same salt and returns
 * 32 bytes of hardware-derived key material. This can be combined with (or
 * used instead of) the Argon2id-derived key, e.g. via HKDF, to require both
 * "something you know" and "something you have" for vault unlock.
 */
export async function authenticateAndDerivePrfKey(
  rpId: string,
  allowCredentialId: Uint8Array,
  evalSalt: Uint8Array,
): Promise<Uint8Array> {
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const assertion = (await navigator.credentials.get({
    publicKey: {
      challenge,
      rpId,
      allowCredentials: [{ id: allowCredentialId, type: 'public-key' }],
      userVerification: 'required',
      extensions: { prf: { eval: { first: evalSalt } } } as AuthenticationExtensionsClientInputs,
      timeout: 60000,
    },
  })) as PublicKeyCredential | null;

  if (!assertion) {
    throw new Error('WebAuthn authentication was cancelled or failed.');
  }

  const extResults = assertion.getClientExtensionResults() as AuthenticationExtensionsClientOutputs & {
    prf?: { results?: { first?: ArrayBuffer } };
  };
  const prfOutput = extResults.prf?.results?.first;
  if (!prfOutput) {
    throw new Error(
      'Authenticator did not return a PRF result. The device may not support the PRF extension.',
    );
  }
  // Run PRF output through HKDF so raw authenticator output is never used directly as a key.
  const baseKey = await crypto.subtle.importKey('raw', prfOutput, 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: new TextEncoder().encode('vault-webauthn-prf-v1'),
      info: new TextEncoder().encode('prf-derived-vault-key'),
    },
    baseKey,
    256,
  );
  return new Uint8Array(bits);
}

// ---------------------------------------------------------------------------
// Shamir's Secret Sharing (3-of-5 emergency social recovery)
// ---------------------------------------------------------------------------

export function splitSecretShamir(secret: Uint8Array, shares = 5, threshold = 3): ShamirShare[] {
  if (threshold > shares) {
    throw new Error('Threshold cannot exceed total share count.');
  }
  const rawShares: Buffer[] = sss.split(Buffer.from(secret), { shares, threshold });
  return rawShares.map((buf: Buffer, i: number) => ({ index: i + 1, data: new Uint8Array(buf) }));
}

export function reconstructSecretShamir(shares: ShamirShare[]): Uint8Array {
  const buffers = shares.map((s) => Buffer.from(s.data));
  const recovered: Buffer = sss.combine(buffers);
  return new Uint8Array(recovered);
}

// ---------------------------------------------------------------------------
// Small binary/text helpers
// ---------------------------------------------------------------------------

export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((sum, a) => sum + a.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    out.set(a, offset);
    offset += a.length;
  }
  return out;
}

export function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary);
}

export function base64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error('Invalid hex string length.');
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}
