import { describe, it, expect } from 'vitest';
import { RatchetTree } from '../tree/ratchet-tree';

describe('ratchet tree arithmetic (RFC 9420 §8.1)', () => {
  it('places leaves at even node indices', () => {
    const t = new RatchetTree(4);
    expect(t.leaves).toEqual([0, 2, 4, 6]);
  });

  it('computes direct path and copath of equal length', () => {
    const t = new RatchetTree(4);
    for (const leaf of t.leaves) {
      expect(t.directPath(leaf).length).toBe(t.copath(leaf).length);
    }
  });

  it('right() descends to a lone trailing leaf in a non-power-of-two tree', () => {
    // 3 leaves -> nodes 0..4, root 3. The right child of the root must reach
    // leaf 4 (not fall off the end), so leaf 4 is covered by the update path.
    const t = new RatchetTree(3);
    const root = t.root();
    expect(t.right(root)).toBe(4);
    // every non-committer leaf appears in some copath resolution of leaf 0
    const targets = t.updatePathTargets(0);
    const reached = new Set(targets.flatMap((x) => x.resolution));
    expect(reached.has(2)).toBe(true);
    expect(reached.has(4)).toBe(true);
  });

  it('siblings are reciprocal', () => {
    const t = new RatchetTree(4);
    for (const leaf of t.leaves) {
      const sib = t.sibling(leaf);
      if (sib !== null) expect(t.sibling(sib)).toBe(leaf);
    }
  });

  it('blanks a removed leaf and its direct path', () => {
    const t = new RatchetTree(4);
    t.removeLeaf(2);
    expect(t.nodes.get(2)?.blank).toBe(true);
    for (const p of t.directPath(2)) {
      expect(t.nodes.get(p)?.blank).toBe(true);
    }
  });
});
