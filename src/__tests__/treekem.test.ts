import { describe, it, expect } from 'vitest';
import { RatchetTree } from '../tree/ratchet-tree';
import { deriveConvergence } from '../tree/treekem';
import { randomBytes } from '../crypto/ciphersuite';
import { createInitialGroupState } from '../group/group-state';
import { commitWithProposals } from '../proposals/commit';

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

describe('convergence proof ties to the LIVE committed epoch (teaching invariant)', () => {
  // The Convergence panel must reproduce the exact commit_secret the key schedule
  // consumed — replaying the captured path secret over the pre-commit tree — so
  // the two panels a learner cross-references show the same bytes, not unrelated
  // fresh randomness.
  for (const proposals of [
    [{ type: 'update', leafIndex: 0 } as const],
    [{ type: 'remove', leafIndex: 4 } as const],
    [{ type: 'add' } as const]
  ]) {
    it(`root secret == epochInputs.commit after ${proposals[0].type}`, async () => {
      const state = createInitialGroupState();
      await commitWithProposals(state, proposals, 0);
      const live = state.lastPathCommit;
      expect(live).not.toBeNull();
      const { committerSecret, rows } = await deriveConvergence(live!.treeBefore, live!.committerLeaf, live!.pathSecret);
      // Every member agrees, and that agreed secret is the epoch's commit_secret.
      for (const r of rows) expect(hex(r.secret)).toBe(hex(committerSecret));
      expect(hex(committerSecret)).toBe(hex(state.epochInputs.commit));
    });
  }
});
