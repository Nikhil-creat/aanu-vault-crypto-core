/**
 * vault-crypto/src/vdf.ts
 *
 * Verifiable Delay Function (Wesolowski construction, simplified) used to
 * provably rate-limit brute-force attempts against a wrapped vault key.
 *
 * Why this matters vs. just "adding a delay": a normal sleep() or iterated
 * hash can be parallelized or skipped by a custom ASIC/FPGA attacker who
 * doesn't run your client code. A VDF is SEQUENTIAL BY CONSTRUCTION — the
 * best known algorithm to compute it requires T sequential squarings, full
 * stop, regardless of parallel hardware. The proof lets a VERIFIER (e.g.
 * the server, or another client) confirm the delay was actually paid
 * without redoing all T squarings itself.
 *
 * This is the classic RSA-group repeated-squaring VDF:
 *   y = x^(2^T) mod N
 * with a Wesolowski proof pi = x^q mod N, where q = floor(2^T / l) and l is
 * a prime derived via Fiat-Shamir from (x, y, T).
 *
 * IMPORTANT CAVEAT: for genuine security, N must be an RSA modulus with an
 * UNKNOWN factorization (a trusted setup, or a well-audited public RSA
 * modulus like the RSA-2048 challenge number) — if you generate N yourself
 * knowing p and q, you can shortcut the delay. This module accepts N as a
 * parameter for exactly that reason: don't call generateOwnModulus() in
 * production, use a modulus from a trusted ceremony or an established
 * VDF network's parameters (e.g. Chia's VDF group parameters).
 */

function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  let result = 1n;
  base = base % mod;
  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % mod;
    exp >>= 1n;
    base = (base * base) % mod;
  }
  return result;
}

function nextPrime(start: bigint): bigint {
  let candidate = start % 2n === 0n ? start + 1n : start;
  while (!isProbablePrimeSimple(candidate)) candidate += 2n;
  return candidate;
}

function isProbablePrimeSimple(n: bigint, rounds = 15): boolean {
  if (n < 2n) return false;
  for (const p of [2n, 3n, 5n, 7n, 11n, 13n]) {
    if (n === p) return true;
    if (n % p === 0n) return false;
  }
  let d = n - 1n;
  let r = 0n;
  while (d % 2n === 0n) {
    d /= 2n;
    r += 1n;
  }
  for (let i = 0; i < rounds; i++) {
    const a = 2n + (BigInt(i * 7919 + 3) % (n - 3n));
    let x = modPow(a, d, n);
    if (x === 1n || x === n - 1n) continue;
    let composite = true;
    for (let j = 0n; j < r - 1n; j++) {
      x = modPow(x, 2n, n);
      if (x === n - 1n) {
        composite = false;
        break;
      }
    }
    if (composite) return false;
  }
  return true;
}

/** Fiat-Shamir challenge prime derived from (N, x, y, T) — makes the proof non-interactive. */
async function fiatShamirPrime(N: bigint, x: bigint, y: bigint, T: number): Promise<bigint> {
  const input = `${N.toString(16)}:${x.toString(16)}:${y.toString(16)}:${T}`;
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(input));
  const bytes = new Uint8Array(digest);
  let hex = '0x';
  for (const b of bytes) hex += b.toString(16).padStart(2, '0');
  // Ensure it's odd and reasonably sized, then bump to nearest prime.
  return nextPrime(BigInt(hex) | 1n);
}

export interface VdfProof {
  y: bigint; // the VDF output
  pi: bigint; // Wesolowski proof
  T: number; // sequential steps (the "delay" parameter)
}

/**
 * Computes the VDF. This function is intentionally sequential — do not try
 * to "optimize" it with parallelism, that would defeat the entire point.
 * T should be tuned so this takes 1-5 seconds on typical hardware for an
 * interactive unlock delay, or much longer for punitive lockout scenarios.
 */
export async function computeVdf(N: bigint, x: bigint, T: number): Promise<VdfProof> {
  let y = x % N;
  for (let i = 0; i < T; i++) {
    y = (y * y) % N;
  }
  const l = await fiatShamirPrime(N, x, y, T);
  // pi = x^floor(2^T / l) mod N, computed via the standard iterative algorithm
  // to avoid materializing a 2^T-sized bigint.
  let q = 0n;
  let r = x % N;
  for (let i = 0; i < T; i++) {
    const b = (2n * r) / l;
    r = (2n * r) % l;
    q = 2n * q + b;
  }
  const pi = modPow(x, q, N);
  return { y, pi, T };
}

/**
 * Verifies a VDF proof in O(log T) time — dramatically cheaper than
 * recomputing the T sequential squarings.
 */
export async function verifyVdf(N: bigint, x: bigint, proof: VdfProof): Promise<boolean> {
  const l = await fiatShamirPrime(N, x, proof.y, proof.T);
  const r = modPow(2n, BigInt(proof.T), l);
  const lhs = (modPow(proof.pi, l, N) * modPow(x, r, N)) % N;
  return lhs === proof.y;
}

/**
 * Derives a rate-limited unlock token: the client must compute a VDF over
 * a challenge before the server (or local device) will release the wrapped
 * key. Failed unlock attempts increase T exponentially (classic lockout
 * backoff, but provable rather than trust-the-client).
 */
export function computeLockoutDelay(failedAttempts: number, baseSteps = 50000): number {
  const capped = Math.min(failedAttempts, 10); // cap growth so it doesn't become effectively infinite
  return baseSteps * Math.pow(2, capped);
}
