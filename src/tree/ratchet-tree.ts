import { x25519 } from '@noble/curves/ed25519.js';
import { randomBytes } from '../crypto/ciphersuite';

function createLeafKeyPair(): { hpkePrivateKey: Uint8Array; hpkePublicKey: Uint8Array } {
  const hpkePrivateKey = randomBytes(32);
  const hpkePublicKey = x25519.getPublicKey(hpkePrivateKey);
  return { hpkePrivateKey, hpkePublicKey };
}

export interface LeafNode {
  leafIndex: number;
  hpkePrivateKey: Uint8Array;
  hpkePublicKey: Uint8Array;
}

export interface ParentNode {
  encryptionKey: Uint8Array;
  parentHash: Uint8Array;
  unmergedLeaves: number[];
}

export interface RatchetNode {
  index: number;
  blank: boolean;
  leafNode?: LeafNode;
  parentNode?: ParentNode;
}

export interface UpdatePathTarget {
  nodeIndex: number;
  resolution: number[];
}

export class RatchetTree {
  readonly leaves: number[] = [];
  readonly nodes = new Map<number, RatchetNode>();

  constructor(memberCount: number) {
    for (let i = 0; i < memberCount; i += 1) {
      this.leaves.push(i * 2);
    }
    for (let i = 0; i < this.nodeWidth(); i += 1) {
      this.nodes.set(i, { index: i, blank: true });
    }
    for (const leafIndex of this.leaves) {
      const kp = createLeafKeyPair();
      this.nodes.set(leafIndex, {
        index: leafIndex,
        blank: false,
        leafNode: {
          leafIndex,
          hpkePrivateKey: kp.hpkePrivateKey,
          hpkePublicKey: kp.hpkePublicKey
        }
      });
    }
  }

  nodeWidth(): number {
    return Math.max(1, this.leaves.length * 2 - 1);
  }

  clone(): RatchetTree {
    const next = new RatchetTree(0);
    next.leaves.splice(0, next.leaves.length, ...this.leaves);
    next.nodes.clear();
    for (const [k, v] of this.nodes.entries()) {
      next.nodes.set(k, structuredClone(v));
    }
    return next;
  }

  addLeaf(): number {
    const blank = this.leaves.find((leaf) => this.nodes.get(leaf)?.blank === true);
    if (blank !== undefined) {
      const node = this.nodes.get(blank);
      if (!node) {
        throw new Error('Leaf not found');
      }
      node.blank = false;
      const kp = createLeafKeyPair();
      node.leafNode = {
        leafIndex: blank,
        hpkePrivateKey: kp.hpkePrivateKey,
        hpkePublicKey: kp.hpkePublicKey
      };
      return blank;
    }

    const leafIndex = this.nodeWidth() + 1;
    this.leaves.push(leafIndex);
    for (let i = 0; i <= this.nodeWidth(); i += 1) {
      if (!this.nodes.has(i)) {
        this.nodes.set(i, { index: i, blank: true });
      }
    }
    const kp = createLeafKeyPair();
    this.nodes.set(leafIndex, {
      index: leafIndex,
      blank: false,
      leafNode: {
        leafIndex,
        hpkePrivateKey: kp.hpkePrivateKey,
        hpkePublicKey: kp.hpkePublicKey
      }
    });
    return leafIndex;
  }

  removeLeaf(leafIndex: number): void {
    const target = this.nodes.get(leafIndex);
    if (!target) {
      return;
    }
    target.blank = true;
    target.leafNode = undefined;
    for (const parent of this.directPath(leafIndex)) {
      const n = this.nodes.get(parent);
      if (n) {
        n.blank = true;
        n.parentNode = undefined;
      }
    }
  }

  root(): number {
    const width = this.nodeWidth();
    let root = 1;
    while (root < width) {
      root = (root << 1) + 1;
    }
    return Math.min(root >> 1, width - 1);
  }

  level(x: number): number {
    let k = 0;
    while (((x >> k) & 1) === 1) {
      k += 1;
    }
    return k;
  }

  parent(x: number): number | null {
    const k = this.level(x);
    const p = (x | (1 << k)) & ~(1 << (k + 1));
    if (p >= this.nodeWidth() || p < 0 || p === x) {
      return null;
    }
    return p;
  }

  left(x: number): number | null {
    const k = this.level(x);
    if (k === 0) {
      return null;
    }
    const l = x ^ (1 << (k - 1));
    return l >= 0 && l < this.nodeWidth() ? l : null;
  }

  right(x: number): number | null {
    const k = this.level(x);
    if (k === 0) {
      return null;
    }
    const r = x ^ (3 << (k - 1));
    return r >= 0 && r < this.nodeWidth() ? r : null;
  }

  sibling(x: number): number | null {
    const p = this.parent(x);
    if (p === null) {
      return null;
    }
    const l = this.left(p);
    const r = this.right(p);
    if (l === x) {
      return r;
    }
    if (r === x) {
      return l;
    }
    return null;
  }

  directPath(leafIndex: number): number[] {
    const out: number[] = [];
    let cursor: number | null = leafIndex;
    while (cursor !== null) {
      const p = this.parent(cursor);
      if (p === null) {
        break;
      }
      out.push(p);
      cursor = p;
    }
    return out;
  }

  copath(leafIndex: number): number[] {
    const out: number[] = [];
    let cursor: number | null = leafIndex;
    while (cursor !== null) {
      const sibling = this.sibling(cursor);
      if (sibling !== null) {
        out.push(sibling);
      }
      cursor = this.parent(cursor);
    }
    return out;
  }

  resolution(nodeIndex: number): number[] {
    const node = this.nodes.get(nodeIndex);
    if (!node || node.blank) {
      const l = this.left(nodeIndex);
      const r = this.right(nodeIndex);
      if (l === null && r === null) {
        return [];
      }
      const leftRes = l === null ? [] : this.resolution(l);
      const rightRes = r === null ? [] : this.resolution(r);
      return [...leftRes, ...rightRes];
    }

    if (node.leafNode) {
      return [nodeIndex];
    }

    const l = this.left(nodeIndex);
    const r = this.right(nodeIndex);
    if (l === null && r === null) {
      return [];
    }

    const leftRes = l === null ? [] : this.resolution(l);
    const rightRes = r === null ? [] : this.resolution(r);
    return [...leftRes, ...rightRes];
  }

  updatePathTargets(leafIndex: number): UpdatePathTarget[] {
    const direct = this.directPath(leafIndex);
    const co = this.copath(leafIndex);
    return direct.map((nodeIndex, i) => ({
      nodeIndex,
      resolution: this.resolution(co[i])
    }));
  }
}
