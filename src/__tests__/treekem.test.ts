import { describe, it, expect } from 'vitest';
import { RatchetTree } from '../tree/ratchet-tree';
import { deriveConvergence } from '../tree/treekem';
import { randomBytes } from '../crypto/ciphersuite';

const hex = (a: Uint8Array) => Array.from(a).map((b) => b.toString(16).padStart(2, '0')).join('');

describe('TreeKEM convergence (the core invariant)', () => {
  for (const n of [2, 3, 4, 5]) {
    it(`every member derives the same root secret in a ${n}-member group`, async () => {
      const tree = new RatchetTree(n);
      const committer = tree.leaves[0];
      const { committerSecret, rows } = await deriveConvergence(tree, committer, randomBytes(32));

      expect(rows).toHaveLength(n);
      for (const row of rows) {
        expect(hex(row.secret)).toBe(hex(committerSecret));
      }
      // Every non-committer must recover it by really decrypting a path secret,
      // not by any fallback shortcut.
      for (const row of rows) {
        if (!row.isCommitter) expect(row.viaDecrypt).toBe(true);
      }
    });
  }

  it('does not mutate the live tree (runs on clones)', async () => {
    const tree = new RatchetTree(4);
    const before = [...tree.nodes.values()].filter((n) => !n.blank).length;
    await deriveConvergence(tree, tree.leaves[1], randomBytes(32));
    const after = [...tree.nodes.values()].filter((n) => !n.blank).length;
    expect(after).toBe(before);
  });
});
