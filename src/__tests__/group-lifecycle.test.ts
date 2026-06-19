import { describe, it, expect } from 'vitest';
import { createInitialGroupState } from '../group/group-state';
import { commitWithProposals } from '../proposals/commit';
import { expandWithLabel } from '../crypto/hkdf';
import { u16be, utf8 } from '../crypto/ciphersuite';

const hex = (a: Uint8Array) => Array.from(a).map((b) => b.toString(16).padStart(2, '0')).join('');

// Same derivation the sender ratchet uses for a leaf's first message key.
function msgKeyNonce(encryptionSecret: Uint8Array, leaf: number) {
  const leafSecret = expandWithLabel(encryptionSecret, 'secret', u16be(leaf), 32);
  return {
    key: expandWithLabel(leafSecret, 'key', new Uint8Array(), 16),
    nonce: expandWithLabel(leafSecret, 'nonce', new Uint8Array(), 12)
  };
}
const AAD = utf8('mls-test-app');

async function seal(enc: Uint8Array, leaf: number, text: string) {
  const { key, nonce } = msgKeyNonce(enc, leaf);
  const k = await crypto.subtle.importKey('raw', key, 'AES-GCM', false, ['encrypt']);
  return new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: AAD }, k, utf8(text)));
}
async function open(enc: Uint8Array, leaf: number, ct: Uint8Array): Promise<string | null> {
  const { key, nonce } = msgKeyNonce(enc, leaf);
  try {
    const k = await crypto.subtle.importKey('raw', key, 'AES-GCM', false, ['decrypt']);
    return new TextDecoder().decode(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce, additionalData: AAD }, k, ct));
  } catch {
    return null;
  }
}

describe('group lifecycle', () => {
  it('advancing an epoch rotates the epoch and encryption secrets (forward secrecy)', async () => {
    const state = createInitialGroupState();
    const epoch0 = hex(state.epochSecret);
    const enc0 = hex(state.epochSecrets.encryption);

    await commitWithProposals(state, [{ type: 'update', leafIndex: 0 }], 0);

    expect(state.epoch).toBe(1);
    expect(hex(state.epochSecret)).not.toBe(epoch0);
    expect(hex(state.epochSecrets.encryption)).not.toBe(enc0);
  });

  it("a removed member cannot decrypt messages from the new epoch", async () => {
    const state = createInitialGroupState(); // Alice(0), Bob(2), Charlie(4)
    const victim = 4;

    // Charlie's last-known encryption secret, before being removed.
    const staleEnc = state.epochSecrets.encryption.slice();

    await commitWithProposals(state, [{ type: 'remove', leafIndex: victim }], 0);

    // The group sends a message in the new epoch (sender = Alice, leaf 0).
    const enc = state.epochSecrets.encryption;
    const ct = await seal(enc, 0, 'post-removal secret');

    // A current member (same epoch secret) reads it; Charlie (stale secret) cannot.
    expect(await open(enc, 0, ct)).toBe('post-removal secret');
    expect(await open(staleEnc, 0, ct)).toBeNull();
  });

  it('adds a member and issues a Welcome without throwing', async () => {
    const state = createInitialGroupState();
    const before = state.activeMembers().length;
    await commitWithProposals(state, [{ type: 'add' }], 0);
    expect(state.activeMembers().length).toBe(before + 1);
    expect(state.epoch).toBe(1);
  });
});
