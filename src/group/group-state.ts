import { randomBytes, sha256Digest, utf8, u16be } from '../crypto/ciphersuite';
import { deriveSecret, expandWithLabel } from '../crypto/hkdf';
import { deriveEpochSecrets, EpochSecrets } from './key-schedule';
import { memberName } from './members';
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

// Plain-English explanation of the most recent action, shown prominently so a
// newcomer always knows what just happened and why it matters.
export interface Narration {
  headline: string;
  lines: string[];
  tone: 'info' | 'success' | 'danger';
}


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
  lastCommitterLeaf: number | null = null;
  ratchets = new Map<number, SenderRatchet>();
  narration: Narration | null = null;
  // Forward-secrecy demo: a per-message key captured in some epoch, kept so we
  // can show it can no longer be re-derived after the epoch advances.
  fsSnapshot: { epoch: number; leaf: number; encHex: string; msgKeyHex: string } | null = null;
  // Guided-tour position (inactive until the user starts it).
  tour: { active: boolean; step: number } = { active: false, step: 0 };
  // Which tree node the learner has clicked to inspect (null = none). Kept in
  // state so the highlight/readout survives a re-render.
  selectedNode: number | null = null;
  // Progressive disclosure: the advanced proof/internals panels start hidden so a
  // newcomer first meets just the tree, controls, and narration. The guided tour
  // reveals each panel as it reaches the concept it teaches; a learner exploring
  // solo can reveal any panel (or all) on demand. Once revealed, a panel stays
  // revealed for the session.
  revealed: Record<string, boolean> = {};

  reveal(key: string): void {
    this.revealed[key] = true;
  }
  // The encryption_secret a member knew in the epoch they were removed in — kept
  // so the access-control demo can show they can no longer read new messages.
  removedSnapshot: { leaf: number; epoch: number; encryptionSecret: Uint8Array } | null = null;
  // Latest convergence-proof result (which members derived which root secret).
  convergence: { committerLeaf: number; tiedToCommit: boolean; commitSecretHex: string; rows: Array<{ leaf: number; isCommitter: boolean; viaDecrypt: boolean; hex: string; match: boolean }> } | null = null;
  // The exact inputs of the last committed TreeKEM path — the committer's leaf,
  // the fresh path secret they chose, and a clone of the tree as it was BEFORE
  // that update mutated it. Replaying deriveConvergence() on these reproduces the
  // real commit_secret this epoch consumed, so the Convergence panel's root
  // secret ties back byte-for-byte to the key schedule's commit_secret chip.
  lastPathCommit: { committerLeaf: number; pathSecret: Uint8Array; treeBefore: RatchetTree } | null = null;
  // Latest access-control demo result.
  accessResult: {
    epoch: number; senderLeaf: number; ctHex: string;
    legitLeaf: number; legitText: string | null;
    removedLeaf: number; removedText: string | null;
  } | null = null;
  // Epoch the UI was last rendered at — used to fire transition animations only
  // when the epoch actually advanced (set to current epoch at construction so
  // the first render is static).
  animEpoch = 0;
  // The two inputs that produced the current epoch's secrets, and the full set
  // of derived secrets — stored so the inspector shows the real, live values.
  epochInputs: { init: Uint8Array; commit: Uint8Array };
  epochSecrets: EpochSecrets;

  activeMembers(): number[] {
    return this.tree.leaves.filter((l) => !this.tree.nodes.get(l)?.blank);
  }

  constructor(tree: RatchetTree) {
    this.tree = tree;
    this.epochInputs = { init: this.initSecret.slice(), commit: this.commitSecret.slice() };
    this.epochSecrets = deriveEpochSecrets(this.initSecret, this.commitSecret);
    this.epochSecret = this.epochSecrets.epoch;
    const encryptionSecret = this.epochSecrets.encryption;
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
      summary: `${memberName(senderLeaf)} → group`,
      detail: text,
      epoch: this.epoch,
      generation: ratchet.appGeneration,
      senderLeaf,
      tag,
      ciphertext: `${ctHex}… (${ciphertext.length}B)`
    });
  }

  seedPcsCompromise(): void {
    this.compromisedPreUpdateSecret = this.epochSecret.slice();
    this.transcript.unshift({
      kind: 'proposal',
      summary: `PCS: ${memberName(0)} marked compromised`,
      detail: `Pre-update epoch secret captured: ${Array.from(this.epochSecret.slice(0, 8)).map((b) => b.toString(16).padStart(2, '0')).join('')}...`,
      epoch: this.epoch
    });
  }

  advanceEpoch(newCommitSecret: Uint8Array, committerLeaf?: number): void {
    this.lastCommitterLeaf = committerLeaf ?? null;
    this.commitSecret = newCommitSecret;
    // The current init_secret (carried from the previous epoch) and this commit's
    // commit_secret are the two inputs to the new epoch's key schedule.
    this.epochInputs = { init: this.initSecret.slice(), commit: this.commitSecret.slice() };
    const secrets = deriveEpochSecrets(this.initSecret, this.commitSecret);
    this.epochSecrets = secrets;
    this.epochSecret = secrets.epoch;
    this.initSecret = secrets.init; // carried forward to seed the next epoch
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
