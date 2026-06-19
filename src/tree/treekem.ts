import { x25519 } from '@noble/curves/ed25519.js';
import { concatBytes, u16be } from '../crypto/ciphersuite';
import { hpkeOpen, hpkeSeal } from '../crypto/hpke';
import { deriveSecret, expandWithLabel } from '../crypto/hkdf';
import { RatchetTree } from './ratchet-tree';

export interface PathCiphertext {
  receiverLeaf: number;
  enc: Uint8Array;
  encryptedPathSecret: Uint8Array;
}

export interface UpdatePathNode {
  nodeIndex: number;
  publicKey: Uint8Array;
  encryptedPathSecrets: PathCiphertext[];
}

export interface TreeKemUpdatePath {
  senderLeafIndex: number;
  nodes: UpdatePathNode[];
  commitSecret: Uint8Array;
}

function derivePrivate(pathSecret: Uint8Array): Uint8Array {
  return deriveSecret(pathSecret, 'node');
}

function pathAad(senderLeafIndex: number, nodeIndex: number, receiverLeaf: number): Uint8Array {
  return concatBytes(u16be(senderLeafIndex), u16be(nodeIndex), u16be(receiverLeaf));
}

export async function generateUpdatePath(tree: RatchetTree, senderLeafIndex: number, pathSecret: Uint8Array): Promise<TreeKemUpdatePath> {
  const targets = tree.updatePathTargets(senderLeafIndex);
  const nodes: UpdatePathNode[] = [];
  let currentPathSecret = pathSecret;

  for (const target of targets) {
    const privateKey = derivePrivate(currentPathSecret);
    const publicKey = x25519.getPublicKey(privateKey);
    const encryptedPathSecrets: PathCiphertext[] = [];

    for (const receiverLeaf of target.resolution) {
      const leafNode = tree.nodes.get(receiverLeaf)?.leafNode;
      if (!leafNode) {
        continue;
      }
      const sealed = await hpkeSeal(leafNode.hpkePublicKey, pathAad(senderLeafIndex, target.nodeIndex, receiverLeaf), currentPathSecret);
      encryptedPathSecrets.push({
        receiverLeaf,
        enc: sealed.enc,
        encryptedPathSecret: sealed.ciphertext
      });
    }

    nodes.push({ nodeIndex: target.nodeIndex, publicKey, encryptedPathSecrets });
    currentPathSecret = expandWithLabel(currentPathSecret, 'path', new Uint8Array(), 32);
  }

  return { senderLeafIndex, nodes, commitSecret: currentPathSecret };
}

export interface ConvergenceRow {
  leaf: number;
  isCommitter: boolean;
  viaDecrypt: boolean;
  secret: Uint8Array;
}

// Teaching helper: prove the core TreeKEM invariant. The committer generates a
// fresh path; every other member then independently recovers the SAME root
// secret — the committer by ratcheting up their direct path, the others by HPKE-
// decrypting exactly one path secret and ratcheting the rest of the way. Runs
// entirely on clones so it never mutates live group state.
export async function deriveConvergence(
  tree: RatchetTree,
  committerLeaf: number,
  pathSecret: Uint8Array
): Promise<{ committerSecret: Uint8Array; rows: ConvergenceRow[] }> {
  const updatePath = await generateUpdatePath(tree, committerLeaf, pathSecret);
  const committerSecret = updatePath.commitSecret;
  const rows: ConvergenceRow[] = [];

  for (const leaf of tree.leaves) {
    if (tree.nodes.get(leaf)?.blank) continue;
    if (leaf === committerLeaf) {
      rows.push({ leaf, isCommitter: true, viaDecrypt: false, secret: committerSecret });
      continue;
    }
    const overlap = updatePath.nodes.some((n) => n.encryptedPathSecrets.some((c) => c.receiverLeaf === leaf));
    const secret = await applyUpdatePath(tree.clone(), updatePath, leaf);
    rows.push({ leaf, isCommitter: false, viaDecrypt: overlap, secret });
  }

  return { committerSecret, rows };
}

export async function applyUpdatePath(tree: RatchetTree, updatePath: TreeKemUpdatePath, receiverLeafIndex: number): Promise<Uint8Array> {
  const overlap = updatePath.nodes.find((n) => n.encryptedPathSecrets.some((c) => c.receiverLeaf === receiverLeafIndex));
  if (!overlap) {
    return updatePath.commitSecret;
  }

  const ct = overlap.encryptedPathSecrets.find((c) => c.receiverLeaf === receiverLeafIndex);
  if (!ct) {
    return updatePath.commitSecret;
  }

  const receiverNode = tree.nodes.get(receiverLeafIndex)?.leafNode;
  if (!receiverNode) {
    return updatePath.commitSecret;
  }

  let pathSecret = await hpkeOpen(
    receiverNode.hpkePrivateKey,
    ct.enc,
    pathAad(updatePath.senderLeafIndex, overlap.nodeIndex, receiverLeafIndex),
    ct.encryptedPathSecret
  );
  const overlapIndex = updatePath.nodes.findIndex((n) => n.nodeIndex === overlap.nodeIndex);
  for (let i = overlapIndex; i < updatePath.nodes.length; i += 1) {
    const node = updatePath.nodes[i];
    const privateKey = derivePrivate(pathSecret);
    const publicKey = x25519.getPublicKey(privateKey);
    const target = tree.nodes.get(node.nodeIndex);
    if (target) {
      target.blank = false;
      target.parentNode = {
        encryptionKey: publicKey,
        parentHash: deriveSecret(pathSecret, 'parent-hash'),
        unmergedLeaves: []
      };
    }
    pathSecret = expandWithLabel(pathSecret, 'path', new Uint8Array(), 32);
  }

  return pathSecret;
}
