/**
 * vault-crypto/src/ratchet.ts
 *
 * Signal-style symmetric-key ratchet for per-record forward secrecy.
 *
 * This is a SYMMETRIC ratchet (KDF chain), not the full Double Ratchet
 * (which also does DH re-keying per message). That's an honest scope
 * choice: a full DH ratchet needs a live back-and-forth between two
 * parties, which doesn't fit "one user encrypting their own vault
 * records." What you get here is the property that matters for a vault:
 * compromise of today's derived key does NOT expose yesterday's records,
 * because each step is one-way (HKDF), and the parent key is wiped
 * after deriving the next one.
 *
 * Chain: rootKey --HKDF--> (recordKey_i, nextChainKey_i) --HKDF--> ...
 */

import { concatBytes, wipe } from './crypto-suite';

export interface RatchetState {
  /** Current chain key. Treat as secret; wipe after deriving next state. */
  chainKey: Uint8Array;
  /** Monotonic counter — also used as AES-GCM associated data to bind key to position. */
  step: number;
}

export interface RatchetOutput {
  recordKey: Uint8Array; // use this to encrypt exactly one record, then discard
  nextState: RatchetState;
}

const RATCHET_INFO_RECORD = new TextEncoder().encode('vault-ratchet-record-key-v1');
const RATCHET_INFO_CHAIN = new TextEncoder().encode('vault-ratchet-chain-key-v1');

export function initRatchet(rootKey: Uint8Array): RatchetState {
  if (rootKey.length !== 32) {
    throw new Error('Ratchet root key must be 32 bytes (derive it from your master key first).');
  }
  return { chainKey: rootKey.slice(), step: 0 };
}

/**
 * Advances the ratchet by one step. Call this once per record you encrypt.
 * The returned `recordKey` is single-use — never reuse it, never persist it.
 */
export async function ratchetStep(state: RatchetState): Promise<RatchetOutput> {
  const baseKey = await crypto.subtle.importKey('raw', state.chainKey, 'HKDF', false, ['deriveBits']);
  const stepBytes = new Uint8Array(new Uint32Array([state.step]).buffer);

  const recordKeyBits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: stepBytes, info: RATCHET_INFO_RECORD },
    baseKey,
    256,
  );
  const nextChainBits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: stepBytes, info: RATCHET_INFO_CHAIN },
    baseKey,
    256,
  );

  const recordKey = new Uint8Array(recordKeyBits);
  const nextChainKey = new Uint8Array(nextChainBits);

  // One-way property: destroy the old chain key material immediately.
  wipe(state.chainKey);

  return {
    recordKey,
    nextState: { chainKey: nextChainKey, step: state.step + 1 },
  };
}

/**
 * Deterministically fast-forwards the ratchet to a target step, e.g. when
 * restoring session state after reload. Requires the state to already be
 * at or before that step — you cannot "rewind" a ratchet (that's the point).
 */
export async function ratchetAdvanceTo(
  state: RatchetState,
  targetStep: number,
): Promise<RatchetState> {
  if (targetStep < state.step) {
    throw new Error('Cannot rewind a ratchet: forward secrecy means past keys are unrecoverable.');
  }
  let current = state;
  while (current.step < targetStep) {
    const { nextState } = await ratchetStep(current);
    current = nextState;
  }
  return current;
}

/** Binds a record key to its ratchet position, so ciphertexts can't be replayed at the wrong step. */
export function ratchetAssociatedData(vaultId: Uint8Array, step: number): Uint8Array {
  const stepBytes = new Uint8Array(new Uint32Array([step]).buffer);
  return concatBytes(vaultId, stepBytes);
}
