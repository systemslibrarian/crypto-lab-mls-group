import { GroupStateModel } from '../group/group-state';
import { memberName } from '../group/members';

export interface RemoveProposal {
  type: 'remove';
  leafIndex: number;
}

export function applyRemove(state: GroupStateModel, leafIndex: number): void {
  state.tree.removeLeaf(leafIndex);
  state.transcript.unshift({
    kind: 'proposal',
    summary: `Remove ${memberName(leafIndex)} (leaf ${leafIndex})`,
    detail: 'Their leaf and every node on their direct path are blanked, so they can derive no future keys',
    epoch: state.epoch
  });
}
