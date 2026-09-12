/**
 * vault-crypto/src/did-recovery.ts
 *
 * Passwordless vault recovery using W3C Decentralized Identifiers (DIDs)
 * and Verifiable Credentials (VCs), following the did:key method (no
 * blockchain or external registry required — the DID is derived directly
 * from a public key, which keeps this self-contained and auditable).
 *
 * Flow:
 *  1. Guardian (a trusted contact, or the user's own secondary device)
 *     holds a DID keypair and issues a Verifiable Credential attesting
 *     "I approve recovery for vault <id>, share index <n>".
 *  2. During recovery, the vault owner collects >= threshold such VCs.
 *  3. Each VC's signature is verified against the guardian's DID before
 *     its attached Shamir share (see crypto-suite.ts) is accepted.
 *
 * This does NOT replace Shamir's Secret Sharing — it's the identity/
 * authorization layer on top of it: proof that a specific, named guardian
 * (not just "whoever has this random-looking file") approved the release
 * of their share.
 *
 * Spec references: did:key (https://w3c-ccg.github.io/did-method-key/),
 * Verifiable Credentials Data Model (https://www.w3.org/TR/vc-data-model/).
 */

import { ed25519 } from '@noble/curves/ed25519';

const MULTICODEC_ED25519_PUB_PREFIX = new Uint8Array([0xed, 0x01]); // multicodec varint for ed25519-pub

export interface DidKeyPair {
  did: string; // e.g. "did:key:z6Mk..."
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

export interface VerifiableCredential {
  '@context': string[];
  type: string[];
  issuer: string; // guardian's DID
  credentialSubject: {
    vaultId: string;
    shareIndex: number;
    action: 'approve-recovery';
    issuedAt: string; // ISO 8601
  };
  proof: {
    type: 'Ed25519Signature2020';
    created: string;
    verificationMethod: string; // issuer DID + key fragment
    signatureBase64: string;
  };
}

// ---------------------------------------------------------------------------
// did:key generation and encoding (base58btc multibase, per spec)
// ---------------------------------------------------------------------------

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function base58Encode(bytes: Uint8Array): string {
  let num = 0n;
  for (const b of bytes) num = (num << 8n) + BigInt(b);
  let encoded = '';
  while (num > 0n) {
    const rem = num % 58n;
    encoded = BASE58_ALPHABET[Number(rem)] + encoded;
    num = num / 58n;
  }
  for (const b of bytes) {
    if (b === 0) encoded = '1' + encoded;
    else break;
  }
  return encoded;
}

function base58Decode(str: string): Uint8Array {
  let num = 0n;
  for (const char of str) {
    const idx = BASE58_ALPHABET.indexOf(char);
    if (idx === -1) throw new Error(`Invalid base58 character: ${char}`);
    num = num * 58n + BigInt(idx);
  }
  const bytes: number[] = [];
  while (num > 0n) {
    bytes.unshift(Number(num % 256n));
    num = num / 256n;
  }
  for (const char of str) {
    if (char === '1') bytes.unshift(0);
    else break;
  }
  return new Uint8Array(bytes);
}

export function generateDidKeyPair(): DidKeyPair {
  const privateKey = ed25519.utils.randomPrivateKey();
  const publicKey = ed25519.getPublicKey(privateKey);
  const multicodecBytes = new Uint8Array(MULTICODEC_ED25519_PUB_PREFIX.length + publicKey.length);
  multicodecBytes.set(MULTICODEC_ED25519_PUB_PREFIX, 0);
  multicodecBytes.set(publicKey, MULTICODEC_ED25519_PUB_PREFIX.length);
  const did = `did:key:z${base58Encode(multicodecBytes)}`;
  return { did, publicKey, privateKey };
}

export function didToPublicKey(did: string): Uint8Array {
  if (!did.startsWith('did:key:z')) throw new Error('Only did:key method is supported.');
  const decoded = base58Decode(did.slice('did:key:z'.length));
  if (decoded[0] !== MULTICODEC_ED25519_PUB_PREFIX[0] || decoded[1] !== MULTICODEC_ED25519_PUB_PREFIX[1]) {
    throw new Error('Unsupported key type in DID (only ed25519 is supported).');
  }
  return decoded.slice(2);
}

// ---------------------------------------------------------------------------
// Verifiable Credential issuance and verification
// ---------------------------------------------------------------------------

function canonicalizeSubject(subject: VerifiableCredential['credentialSubject']): Uint8Array {
  // Deterministic field ordering for signing (a production system should use
  // full JSON-LD canonicalization / URDNA2015; this fixed-order JSON is a
  // pragmatic substitute that is still deterministic and collision-safe
  // for this fixed schema).
  const ordered = {
    vaultId: subject.vaultId,
    shareIndex: subject.shareIndex,
    action: subject.action,
    issuedAt: subject.issuedAt,
  };
  return new TextEncoder().encode(JSON.stringify(ordered));
}

export function issueRecoveryCredential(
  guardian: DidKeyPair,
  vaultId: string,
  shareIndex: number,
): VerifiableCredential {
  const issuedAt = new Date().toISOString();
  const subject: VerifiableCredential['credentialSubject'] = {
    vaultId,
    shareIndex,
    action: 'approve-recovery',
    issuedAt,
  };
  const message = canonicalizeSubject(subject);
  const signature = ed25519.sign(message, guardian.privateKey);

  return {
    '@context': ['https://www.w3.org/2018/credentials/v1'],
    type: ['VerifiableCredential', 'VaultRecoveryApproval'],
    issuer: guardian.did,
    credentialSubject: subject,
    proof: {
      type: 'Ed25519Signature2020',
      created: issuedAt,
      verificationMethod: `${guardian.did}#key-1`,
      signatureBase64: bytesToBase64(signature),
    },
  };
}

export function verifyRecoveryCredential(vc: VerifiableCredential, expectedVaultId: string): boolean {
  if (vc.credentialSubject.vaultId !== expectedVaultId) return false;
  if (vc.credentialSubject.action !== 'approve-recovery') return false;
  try {
    const publicKey = didToPublicKey(vc.issuer);
    const message = canonicalizeSubject(vc.credentialSubject);
    const signature = base64ToBytes(vc.proof.signatureBase64);
    return ed25519.verify(signature, message, publicKey);
  } catch {
    return false;
  }
}

/**
 * Given a threshold and a set of collected VCs, checks that enough DISTINCT,
 * validly-signed guardian approvals exist before releasing Shamir shares.
 * (Pair each vc.credentialSubject.shareIndex with the matching ShamirShare
 * from crypto-suite.ts before calling reconstructSecretShamir.)
 */
export function hasSufficientApprovals(
  vcs: VerifiableCredential[],
  vaultId: string,
  threshold: number,
): boolean {
  const validIssuers = new Set<string>();
  for (const vc of vcs) {
    if (verifyRecoveryCredential(vc, vaultId)) {
      validIssuers.add(vc.issuer);
    }
  }
  return validIssuers.size >= threshold;
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

function base64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}
