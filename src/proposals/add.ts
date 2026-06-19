import { GroupStateModel } from '../group/group-state';
import { memberName } from '../group/members';

export interface AddProposal {
  type: 'add';
}

export function applyAdd(state: GroupStateModel): number {
  const leaf = state.tree.addLeaf();
  state.transcript.unshift({
    kind: 'proposal',
    summary: `Add ${memberName(leaf)} (leaf ${leaf})`,
    detail: 'Placed at the leftmost blank leaf, or the tree was grown by one level',
    epoch: state.epoch
  });
  return leaf;
}
