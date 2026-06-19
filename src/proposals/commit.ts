import { randomBytes } from '../crypto/ciphersuite';
import { buildWelcome, describeWelcome } from '../group/welcome';
import { GroupStateModel } from '../group/group-state';
import { memberName } from '../group/members';
import { applyAdd, AddProposal } from './add';
import { applyRemove, RemoveProposal } from './remove';
import { applyUpdate, UpdateProposal } from './update';

type Proposal = AddProposal | RemoveProposal | UpdateProposal;

function isUpdate(p: Proposal): p is UpdateProposal {
  return p.type === 'update';
}

function isRemove(p: Proposal): p is RemoveProposal {
  return p.type === 'remove';
}

function isAdd(p: Proposal): p is AddProposal {
  return p.type === 'add';
}

export async function commitWithProposals(state: GroupStateModel, proposals: Proposal[], committerLeaf: number): Promise<void> {
  const updates = proposals.filter(isUpdate);
  const removes = proposals.filter(isRemove);
  const adds = proposals.filter(isAdd);

  let commitSecret = randomBytes(32);
  for (const update of updates) {
    commitSecret = await applyUpdate(state, update.leafIndex);
  }
  for (const remove of removes) {
    applyRemove(state, remove.leafIndex);
  }

  const addedLeaves: number[] = [];
  for (const add of adds) {
    if (add.type === 'add') {
      addedLeaves.push(applyAdd(state));
    }
  }

  const committerCommitSecret = await applyUpdate(state, committerLeaf);
  commitSecret = committerCommitSecret;

  state.advanceEpoch(commitSecret, committerLeaf);
  void state.updateTranscriptHashes(`commit:${state.epoch}:${committerLeaf}`);
  state.transcript.unshift({
    kind: 'commit',
    summary: `Commit by ${memberName(committerLeaf)} → epoch ${state.epoch}`,
    detail: `Applied ${updates.length} update(s), ${removes.length} remove(s), ${adds.length} add(s); a new epoch secret now governs the group`,
    epoch: state.epoch
  });

  if (addedLeaves.length > 0) {
    const groupInfo = new TextEncoder().encode(JSON.stringify({
      epoch: state.epoch,
      confirmedTranscriptHash: Array.from(state.confirmedTranscriptHash)
    }));
    void buildWelcome(
      state.tree,
      addedLeaves,
      { joinerSecret: state.epochSecret, pathSecret: commitSecret, psks: [] },
      groupInfo
    ).then((welcome) => {
      state.transcript.unshift({
        kind: 'welcome',
        summary: 'Welcome message',
        detail: describeWelcome(welcome),
        epoch: state.epoch
      });
    });
  }
}
