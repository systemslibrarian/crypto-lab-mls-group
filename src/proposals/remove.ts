import { GroupStateModel } from '../group/group-state';

export interface RemoveProposal {
  type: 'remove';
  leafIndex: number;
}

export function applyRemove(state: GroupStateModel, leafIndex: number): void {
  state.tree.removeLeaf(leafIndex);
  state.transcript.unshift({
    kind: 'proposal',
    summary: `Remove proposal leaf ${leafIndex}`,
    detail: 'Leaf and direct path blanked',
    epoch: state.epoch
  });
}
