import { randomBytes, sha256Digest, utf8 } from '../crypto/ciphersuite';
import { deriveSecret } from '../crypto/hkdf';
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
}

export type ScenarioId = 'add-dave' | 'remove-bob' | 'pcs' | 'churn';

interface SenderRatchet {
  handshakeGeneration: number;
  appGeneration: number;
  appSecret: Uint8Array;
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
    for (const leaf of tree.leaves) {
      this.ratchets.set(leaf, { handshakeGeneration: 0, appGeneration: 0, appSecret: deriveSecret(this.epochSecret, `app-${leaf}`) });
    }
  }

  async updateTranscriptHashes(payload: string): Promise<void> {
    const confirmed = await sha256Digest(new Uint8Array([...this.confirmedTranscriptHash, ...utf8(payload)]));
    this.confirmedTranscriptHash = confirmed;
    this.interimTranscriptHash = await sha256Digest(new Uint8Array([...confirmed, ...utf8('confirmation')]));
  }

  sendApplication(senderLeaf: number, text: string): void {
    const ratchet = this.ratchets.get(senderLeaf);
    if (!ratchet) {
      return;
    }

    ratchet.appGeneration += 1;
    ratchet.appSecret = deriveSecret(ratchet.appSecret, 'app');
    const tag = Array.from(deriveSecret(ratchet.appSecret, 'tag').slice(0, 8)).map((b) => b.toString(16).padStart(2, '0')).join('');

    this.transcript.unshift({
      kind: 'application',
      summary: `msg from leaf ${senderLeaf}`,
      detail: text,
      epoch: this.epoch,
      generation: ratchet.appGeneration,
      senderLeaf,
      tag
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
  }
}

export function createInitialGroupState(): GroupStateModel {
  const tree = new RatchetTree(3);
  return new GroupStateModel(tree);
}
