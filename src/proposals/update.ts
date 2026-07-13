import { randomBytes } from '../crypto/ciphersuite';
import { GroupStateModel } from '../group/group-state';
import { memberName } from '../group/members';
import { applyUpdatePath, generateUpdatePath } from '../tree/treekem';

export interface UpdateProposal {
  type: 'update';
  leafIndex: number;
}

export async function applyUpdate(state: GroupStateModel, leafIndex: number): Promise<Uint8Array> {
  const pathSecret = randomBytes(32);
  // Snapshot the tree and the fresh path secret BEFORE this update mutates the
  // tree, so the TreeKEM Convergence panel can replay this exact commit and
  // reproduce the very same commit_secret the key schedule then consumes. This
  // is the real committed material, not a fresh random path.
  state.lastPathCommit = {
    committerLeaf: leafIndex,
    pathSecret: pathSecret.slice(),
    treeBefore: state.tree.clone()
  };
  const updatePath = await generateUpdatePath(state.tree, leafIndex, pathSecret);

  for (const leaf of state.tree.leaves) {
    if (leaf === leafIndex) {
      continue;
    }
    await applyUpdatePath(state.tree, updatePath, leaf);
  }

  state.transcript.unshift({
    kind: 'proposal',
    summary: `Update by ${memberName(leafIndex)} (leaf ${leafIndex})`,
    detail: `Fresh keys for direct-path nodes ${updatePath.nodes.map((n) => n.nodeIndex).join(', ')}, each encrypted to its copath subtree`,
    epoch: state.epoch
  });

  return updatePath.commitSecret;
}
