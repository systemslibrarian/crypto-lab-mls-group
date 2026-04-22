import { randomBytes, sha256Digest, utf8, u16be } from '../crypto/ciphersuite';
import { deriveSecret, expandWithLabel } from '../crypto/hkdf';
import { deriveEpochSecrets } from './key-schedule';
import { RatchetTree } from '../tree/ratchet-tree';

export interface TranscriptEntry {
  kind: 'proposal' | 'commit' | 'welcome' | 'application';
  summary: string;
  detail: string;
  epoch: number;
  generation?: number;
  senderLeaf?: number;
  tag?: string;
  ciphertext?: string;
}

export type ScenarioId = 'add-dave' | 'remove-bob' | 'pcs' | 'churn';

interface SenderRatchet {
  handshakeGeneration: number;
  appGeneration: number;
  appSecret: Uint8Array;
}

// RFC 9420 §15.3 — per-generation key/nonce derivation from application ratchet
async function privateMessageEncrypt(
  appSecret: Uint8Array,
  generation: number,
  senderLeaf: number,
  epoch: number,
  plaintext: Uint8Array
): Promise<{ ciphertext: Uint8Array; tag: string }> {
  const key   = expandWithLabel(appSecret, 'key',        new Uint8Array(), 16);
  const nonce = expandWithLabel(appSecret, 'nonce',      new Uint8Array(), 12);
  const reuseGuard = randomBytes(4);
  // XOR reuse_guard into nonce bytes 8–11 per RFC 9420 §15.4
  const finalNonce = new Uint8Array(nonce);
  for (let i = 0; i < 4; i++) finalNonce[8 + i] ^= reuseGuard[i];

  const aad = utf8(JSON.stringify({ epoch, generation, senderLeaf, content_type: 'application' }));
  const k = await crypto.subtle.importKey('raw', key, 'AES-GCM', false, ['encrypt']);
  const out = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: finalNonce, additionalData: aad }, k, plaintext));

  // AEAD tag = last 16 bytes of AES-GCM output
  const tag = Array.from(out.slice(-16)).map((b) => b.toString(16).padStart(2, '0')).join('');
  return { ciphertext: out, tag };
}

// Seed a fresh ratchet for a leaf from the epoch's encryption_secret (RFC 9420 §15.2)
function seedRatchet(encryptionSecret: Uint8Array, leafIndex: number): SenderRatchet {
  const leafIndexBytes = u16be(leafIndex);
  const appSecret = expandWithLabel(encryptionSecret, 'secret', leafIndexBytes, 32);
  return { handshakeGeneration: 0, appGeneration: 0, appSecret };
}

export class GroupStateModel {
  epoch = 0;
  tree: RatchetTree;
  transcript: TranscriptEntry[] = [];
  initSecret = randomBytes(32);
  commitSecret = randomBytes(32);
  epochSecret = randomBytes(32);
  confirmedTranscriptHash = new Uint8Array(32);
  interimTranscriptHash = new Uint8Array(32);
  compromisedPreUpdateSecret: Uint8Array | null = null;
  ratchets = new Map<number, SenderRatchet>();

  constructor(tree: RatchetTree) {
    this.tree = tree;
    const encryptionSecret = deriveSecret(this.epochSecret, 'encryption');
    for (const leaf of tree.leaves) {
      this.ratchets.set(leaf, seedRatchet(encryptionSecret, leaf));
    }
  }

  async updateTranscriptHashes(payload: string): Promise<void> {
    const confirmed = await sha256Digest(new Uint8Array([...this.confirmedTranscriptHash, ...utf8(payload)]));
    this.confirmedTranscriptHash = confirmed;
    this.interimTranscriptHash = await sha256Digest(new Uint8Array([...confirmed, ...utf8('confirmation')]));
  }

  async sendApplication(senderLeaf: number, text: string): Promise<void> {
    const ratchet = this.ratchets.get(senderLeaf);
    if (!ratchet) {
      return;
    }

    ratchet.appGeneration += 1;
    // Advance the ratchet first, derive key/nonce from current appSecret
    const { ciphertext, tag } = await privateMessageEncrypt(
      ratchet.appSecret,
      ratchet.appGeneration,
      senderLeaf,
      this.epoch,
      utf8(text)
    );
    // Advance ratchet secret after use (forward secrecy)
    ratchet.appSecret = deriveSecret(ratchet.appSecret, 'app');

    const ctHex = Array.from(ciphertext.slice(0, 12)).map((b) => b.toString(16).padStart(2, '0')).join('');

    this.transcript.unshift({
      kind: 'application',
      summary: `msg from leaf ${senderLeaf}`,
      detail: text,
      epoch: this.epoch,
      generation: ratchet.appGeneration,
      senderLeaf,
      tag,
      ciphertext: `${ctHex}… (${ciphertext.length}B)`
    });
  }

  seedScenario(id: ScenarioId): void {
    if (id === 'add-dave') {
      this.transcript.unshift({ kind: 'proposal', summary: 'Preset: add Dave', detail: 'Alice/Bob/Charlie then add Dave', epoch: this.epoch });
      return;
    }

    if (id === 'remove-bob') {
      this.transcript.unshift({ kind: 'proposal', summary: 'Preset: remove Bob', detail: '5-member group, Bob removed, direct path blanked', epoch: this.epoch });
      return;
    }

    if (id === 'pcs') {
      this.compromisedPreUpdateSecret = this.epochSecret.slice();
      this.transcript.unshift({ kind: 'proposal', summary: 'Preset: PCS recovery', detail: 'Alice compromised then updates direct path', epoch: this.epoch });
      return;
    }

    for (let i = 0; i < 20; i += 1) {
      this.epoch += 1;
      this.transcript.unshift({ kind: 'commit', summary: `Churn commit #${i + 1}`, detail: 'Rapid add/remove/update cycle', epoch: this.epoch });
    }
  }

  advanceEpoch(newCommitSecret: Uint8Array): void {
    this.commitSecret = newCommitSecret;
    const secrets = deriveEpochSecrets(this.initSecret, this.commitSecret);
    this.epochSecret = secrets.epoch;
    this.initSecret = secrets.init;
    this.epoch += 1;
    // Reseed all ratchets from the new epoch's encryption_secret (RFC 9420 §15.2)
    const encryptionSecret = secrets.encryption;
    this.ratchets.clear();
    for (const leaf of this.tree.leaves) {
      if (!this.tree.nodes.get(leaf)?.blank) {
        this.ratchets.set(leaf, seedRatchet(encryptionSecret, leaf));
      }
    }
  }
}

export function createInitialGroupState(): GroupStateModel {
  const tree = new RatchetTree(3);
  return new GroupStateModel(tree);
}
