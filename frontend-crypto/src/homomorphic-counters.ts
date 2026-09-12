/**
 * vault-crypto/src/homomorphic-counters.ts
 *
 * Partial Homomorphic Encryption (Paillier cryptosystem) for server-side
 * counters — e.g. "records stored", "searches performed", "storage bytes
 * used" — that the server can INCREMENT and later report a running total
 * for, without ever seeing individual plaintext values.
 *
 * Why Paillier and not full FHE here: Paillier only needs additive
 * homomorphism (E(a) * E(b) = E(a+b)) which is exactly what a counter
 * needs, is ~1000x cheaper than CKKS/BFV FHE, and has a 20+ year track
 * record. The heavier CKKS/OpenFHE machinery is reserved for the
 * encrypted-search index in Section 3, where you actually need range/
 * equality comparisons over ciphertexts.
 *
 * This implementation uses bigint arithmetic directly (no native deps),
 * following the standard Paillier construction. Key sizes: use >= 2048-bit
 * primes in production (below defaults to 2048-bit modulus).
 */

export interface PaillierPublicKey {
  n: bigint; // modulus = p * q
  g: bigint; // generator, = n + 1 in the simplified/optimized variant
  nSquared: bigint;
}

export interface PaillierPrivateKey {
  lambda: bigint; // lcm(p-1, q-1)
  mu: bigint; // modular inverse used in decryption
  publicKey: PaillierPublicKey;
}

export interface PaillierCiphertext {
  value: bigint;
}

// ---------------------------------------------------------------------------
// Number theory helpers
// ---------------------------------------------------------------------------

function gcd(a: bigint, b: bigint): bigint {
  while (b) {
    [a, b] = [b, a % b];
  }
  return a;
}

function lcm(a: bigint, b: bigint): bigint {
  return (a / gcd(a, b)) * b;
}

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

function modInverse(a: bigint, mod: bigint): bigint {
  // Extended Euclidean algorithm
  let [oldR, r] = [a, mod];
  let [oldS, s] = [1n, 0n];
  while (r !== 0n) {
    const q = oldR / r;
    [oldR, r] = [r, oldR - q * r];
    [oldS, s] = [s, oldS - q * s];
  }
  if (oldR !== 1n) throw new Error('Modular inverse does not exist (inputs not coprime).');
  return ((oldS % mod) + mod) % mod;
}

function randomBigInt(bitLength: number): bigint {
  const bytes = new Uint8Array(Math.ceil(bitLength / 8));
  crypto.getRandomValues(bytes);
  bytes[0] |= 0x80; // ensure top bit set -> correct bit length
  let hex = '0x';
  for (const b of bytes) hex += b.toString(16).padStart(2, '0');
  return BigInt(hex);
}

function isProbablePrime(n: bigint, rounds = 20): boolean {
  if (n < 2n) return false;
  for (const p of [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n]) {
    if (n === p) return true;
    if (n % p === 0n) return false;
  }
  let d = n - 1n;
  let r = 0n;
  while (d % 2n === 0n) {
    d /= 2n;
    r += 1n;
  }
  witnessLoop: for (let i = 0; i < rounds; i++) {
    const a = (randomBigInt(n.toString(2).length - 1) % (n - 3n)) + 2n;
    let x = modPow(a, d, n);
    if (x === 1n || x === n - 1n) continue;
    for (let j = 0n; j < r - 1n; j++) {
      x = modPow(x, 2n, n);
      if (x === n - 1n) continue witnessLoop;
    }
    return false;
  }
  return true;
}

function generatePrime(bitLength: number): bigint {
  let candidate: bigint;
  do {
    candidate = randomBigInt(bitLength);
    if (candidate % 2n === 0n) candidate += 1n;
  } while (!isProbablePrime(candidate));
  return candidate;
}

// ---------------------------------------------------------------------------
// Paillier keygen / encrypt / decrypt / homomorphic add
// ---------------------------------------------------------------------------

export function generatePaillierKeyPair(bitLength = 2048): {
  publicKey: PaillierPublicKey;
  privateKey: PaillierPrivateKey;
} {
  const half = bitLength / 2;
  let p: bigint, q: bigint, n: bigint;
  do {
    p = generatePrime(half);
    q = generatePrime(half);
    n = p * q;
  } while (p === q || n.toString(2).length !== bitLength);

  const nSquared = n * n;
  const g = n + 1n; // standard optimization: g = n+1 works when using the (1+n)^m trick
  const lambda = lcm(p - 1n, q - 1n);
  // With g = n+1, L(g^lambda mod n^2) = lambda mod n, so mu = (lambda mod n)^-1 mod n
  const mu = modInverse(lambda % n, n);

  const publicKey: PaillierPublicKey = { n, g, nSquared };
  const privateKey: PaillierPrivateKey = { lambda, mu, publicKey };
  return { publicKey, privateKey };
}

/** Encrypts a non-negative integer counter value. */
export function paillierEncrypt(publicKey: PaillierPublicKey, plaintext: bigint): PaillierCiphertext {
  if (plaintext < 0n || plaintext >= publicKey.n) {
    throw new Error('Plaintext must satisfy 0 <= m < n.');
  }
  let r: bigint;
  do {
    r = randomBigInt(publicKey.n.toString(2).length) % publicKey.n;
  } while (r === 0n || gcd(r, publicKey.n) !== 1n);

  // c = g^m * r^n mod n^2, with g = n+1 optimized as (1 + m*n mod n^2)
  const gm = (1n + plaintext * publicKey.n) % publicKey.nSquared;
  const rn = modPow(r, publicKey.n, publicKey.nSquared);
  const value = (gm * rn) % publicKey.nSquared;
  return { value };
}

export function paillierDecrypt(privateKey: PaillierPrivateKey, ciphertext: PaillierCiphertext): bigint {
  const { n, nSquared } = privateKey.publicKey;
  const u = modPow(ciphertext.value, privateKey.lambda, nSquared);
  const l = (u - 1n) / n; // L(x) = (x-1)/n, exact integer division by construction
  return (l * privateKey.mu) % n;
}

/** Homomorphic addition: decrypting the result yields plaintext_a + plaintext_b, server never sees either. */
export function paillierAdd(
  publicKey: PaillierPublicKey,
  a: PaillierCiphertext,
  b: PaillierCiphertext,
): PaillierCiphertext {
  return { value: (a.value * b.value) % publicKey.nSquared };
}

/** Homomorphic scalar multiplication: decrypting yields plaintext * scalar. */
export function paillierMultiplyScalar(
  publicKey: PaillierPublicKey,
  ciphertext: PaillierCiphertext,
  scalar: bigint,
): PaillierCiphertext {
  return { value: modPow(ciphertext.value, scalar, publicKey.nSquared) };
}

/**
 * Server-side counter object. The server calls `increment` repeatedly and
 * can persist/transmit `ciphertext`, but has no decryption capability —
 * only the client (holding privateKey) can ever read the running total.
 */
export class HomomorphicCounter {
  private ciphertext: PaillierCiphertext;

  constructor(private publicKey: PaillierPublicKey, initial?: PaillierCiphertext) {
    this.ciphertext = initial ?? paillierEncrypt(publicKey, 0n);
  }

  /** Server calls this with a client-supplied encrypted delta (e.g. encrypt(1) per event). */
  increment(encryptedDelta: PaillierCiphertext): void {
    this.ciphertext = paillierAdd(this.publicKey, this.ciphertext, encryptedDelta);
  }

  serialize(): string {
    return this.ciphertext.value.toString();
  }

  getCiphertext(): PaillierCiphertext {
    return this.ciphertext;
  }
}
