import { GroupStateModel } from '../group/group-state';

export interface AddProposal {
  type: 'add';
}

export function applyAdd(state: GroupStateModel): number {
  const leaf = state.tree.addLeaf();
  state.transcript.unshift({
    kind: 'proposal',
    summary: `Add proposal leaf ${leaf}`,
    detail: 'Appended at leftmost blank or extended tree',
    epoch: state.epoch
  });
  return leaf;
}
