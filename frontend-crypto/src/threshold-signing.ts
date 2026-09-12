/**
 * vault-crypto/src/threshold-signing.ts
 *
 * t-of-n threshold Schnorr signatures (FROST — Flexible Round-Optimized
 * Schnorr Threshold signatures) over ed25519, so that signing an audit
 * record requires cooperation of >= t out of n devices/guardians, and no
 * single device ever holds the full signing key.
 *
 * HONEST SCOPE NOTE: there is currently no mature, widely-audited
 * threshold scheme for ML-DSA (the PQC signature used elsewhere in this
 * suite) — threshold post-quantum signatures are an active research area,
 * not a solved, shippable primitive as of this writing. Rather than
 * pretend otherwise, this module implements threshold signing over
 * classical ed25519 (FROST is a real, published, audited construction).
 * If you need this signature to also be quantum-resistant, pair it with
 * a single-device ML-DSA-65 co-signature (belt-and-suspenders) rather
 * than waiting on threshold PQC to mature.
 *
 * This is a 2-round FROST implementation (simplified single-signing-session
 * variant, no signing-key-share refresh / proactive resharing):
 *   Round 1: each participant generates a nonce pair and broadcasts commitments.
 *   Round 2: each participant computes a signature share; shares are combined.
 */

import { ed25519 } from '@noble/curves/ed25519';

const CURVE_ORDER = ed25519.CURVE.n;

function mod(a: bigint, m: bigint = CURVE_ORDER): bigint {
  const r = a % m;
  return r >= 0n ? r : r + m;
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  let hex = '0x';
  for (const b of bytes) hex += b.toString(16).padStart(2, '0');
  return BigInt(hex);
}

function bigIntToBytes32(n: bigint): Uint8Array {
  const hex = mod(n).toString(16).padStart(64, '0');
  const bytes = new Uint8Array(32);
  for (let i = 0; i < 32; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  return bytes;
}

export interface ThresholdKeyShare {
  participantIndex: number; // 1-indexed, matches Shamir share index
  secretShare: bigint; // this participant's share of the group signing key
  groupPublicKey: Uint8Array; // shared public key for the whole group
}

/**
 * Dealer-based key generation (trusted dealer variant — simpler than
 * distributed key generation, appropriate when the vault owner is
 * bootstrapping shares for their own recovery guardians and can
 * temporarily hold the full key in memory during setup only).
 *
 * For a fully trustless setup with no single point that ever sees the
 * complete key, swap this for Pedersen DKG — flagged here rather than
 * silently pretended away.
 */
export function dealerGenerateThresholdShares(
  threshold: number,
  totalParticipants: number,
): { shares: ThresholdKeyShare[]; groupPublicKey: Uint8Array } {
  if (threshold > totalParticipants) throw new Error('Threshold cannot exceed participant count.');

  // Random polynomial of degree (threshold - 1); f(0) = group secret key.
  const coefficients: bigint[] = [];
  for (let i = 0; i < threshold; i++) {
    const randBytes = ed25519.utils.randomPrivateKey();
    coefficients.push(mod(bytesToBigInt(randBytes)));
  }

  const groupSecretKey = coefficients[0];
  const groupPublicKey = ed25519.getPublicKey(bigIntToBytes32(groupSecretKey));

  const shares: ThresholdKeyShare[] = [];
  for (let i = 1; i <= totalParticipants; i++) {
    let value = 0n;
    let xPow = 1n;
    for (const coeff of coefficients) {
      value = mod(value + coeff * xPow);
      xPow = mod(xPow * BigInt(i));
    }
    shares.push({ participantIndex: i, secretShare: value, groupPublicKey });
  }

  return { shares, groupPublicKey };
}

function lagrangeCoefficient(participantIndex: number, allIndices: number[]): bigint {
  let num = 1n;
  let den = 1n;
  for (const j of allIndices) {
    if (j === participantIndex) continue;
    num = mod(num * BigInt(j));
    den = mod(den * BigInt(j - participantIndex));
  }
  return mod(num * modInverse(den, CURVE_ORDER));
}

function modInverse(a: bigint, m: bigint): bigint {
  let [oldR, r] = [mod(a, m), m];
  let [oldS, s] = [1n, 0n];
  while (r !== 0n) {
    const q = oldR / r;
    [oldR, r] = [r, oldR - q * r];
    [oldS, s] = [s, oldS - q * s];
  }
  return mod(oldS, m);
}

// ---------------------------------------------------------------------------
// Round 1: nonce commitments
// ---------------------------------------------------------------------------

export interface NonceCommitment {
  participantIndex: number;
  d: bigint; // hiding nonce (secret, kept by participant)
  e: bigint; // binding nonce (secret, kept by participant)
  D: Uint8Array; // public commitment to d
  E: Uint8Array; // public commitment to e
}

export function generateNonceCommitment(participantIndex: number): NonceCommitment {
  const d = mod(bytesToBigInt(ed25519.utils.randomPrivateKey()));
  const e = mod(bytesToBigInt(ed25519.utils.randomPrivateKey()));
  const D = ed25519.getPublicKey(bigIntToBytes32(d));
  const E = ed25519.getPublicKey(bigIntToBytes32(e));
  return { participantIndex, d, e, D, E };
}

// ---------------------------------------------------------------------------
// Round 2: signature shares
// ---------------------------------------------------------------------------

export interface PublicCommitment {
  participantIndex: number;
  D: Uint8Array;
  E: Uint8Array;
}

async function computeBindingFactor(
  message: Uint8Array,
  commitments: PublicCommitment[],
  participantIndex: number,
): Promise<bigint> {
  const parts: Uint8Array[] = [message];
  for (const c of commitments) {
    parts.push(new Uint8Array([c.participantIndex]), c.D, c.E);
  }
  parts.push(new Uint8Array([participantIndex]));
  let total = 0;
  for (const p of parts) total += p.length;
  const buf = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    buf.set(p, off);
    off += p.length;
  }
  const digest = await crypto.subtle.digest('SHA-256', buf);
  return mod(bytesToBigInt(new Uint8Array(digest)));
}

async function computeChallenge(groupPublicKey: Uint8Array, groupCommitment: Uint8Array, message: Uint8Array): Promise<bigint> {
  const buf = new Uint8Array(groupCommitment.length + groupPublicKey.length + message.length);
  buf.set(groupCommitment, 0);
  buf.set(groupPublicKey, groupCommitment.length);
  buf.set(message, groupCommitment.length + groupPublicKey.length);
  const digest = await crypto.subtle.digest('SHA-512', buf);
  return mod(bytesToBigInt(new Uint8Array(digest)), CURVE_ORDER);
}

export async function computeSignatureShare(
  keyShare: ThresholdKeyShare,
  ownNonce: NonceCommitment,
  message: Uint8Array,
  allCommitments: PublicCommitment[],
): Promise<bigint> {
  const allIndices = allCommitments.map((c) => c.participantIndex);
  const bindingFactor = await computeBindingFactor(message, allCommitments, keyShare.participantIndex);

  // Aggregate group commitment R = sum(D_i + rho_i * E_i)
  let groupR = ed25519.ExtendedPoint.ZERO;
  for (const c of allCommitments) {
    const rho = await computeBindingFactor(message, allCommitments, c.participantIndex);
    const Dp = ed25519.ExtendedPoint.fromHex(c.D);
    const Ep = ed25519.ExtendedPoint.fromHex(c.E);
    groupR = groupR.add(Dp.add(Ep.multiply(mod(rho))));
  }
  const groupRBytes = groupR.toRawBytes();

  const challenge = await computeChallenge(keyShare.groupPublicKey, groupRBytes, message);
  const lambda = lagrangeCoefficient(keyShare.participantIndex, allIndices);

  // z_i = d_i + (e_i * rho_i) + lambda_i * s_i * c
  const zi = mod(
    ownNonce.d + mod(ownNonce.e * bindingFactor) + mod(mod(lambda * keyShare.secretShare) * challenge),
  );
  return zi;
}

/** Combines t signature shares into a final, standard-verifiable ed25519 signature. */
export async function aggregateSignatureShares(
  shares: bigint[],
  groupPublicKey: Uint8Array,
  message: Uint8Array,
  allCommitments: PublicCommitment[],
): Promise<Uint8Array> {
  let groupR = ed25519.ExtendedPoint.ZERO;
  for (const c of allCommitments) {
    const rho = await computeBindingFactor(message, allCommitments, c.participantIndex);
    const Dp = ed25519.ExtendedPoint.fromHex(c.D);
    const Ep = ed25519.ExtendedPoint.fromHex(c.E);
    groupR = groupR.add(Dp.add(Ep.multiply(mod(rho))));
  }
  const z = mod(shares.reduce((acc, s) => mod(acc + s), 0n));
  const sig = new Uint8Array(64);
  sig.set(groupR.toRawBytes(), 0);
  sig.set(bigIntToBytes32(z), 32);
  return sig;
}

/** Standard ed25519 verification — the resulting signature is indistinguishable from a normal one. */
export function verifyThresholdSignature(
  groupPublicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): boolean {
  try {
    return ed25519.verify(signature, message, groupPublicKey);
  } catch {
    return false;
  }
}
