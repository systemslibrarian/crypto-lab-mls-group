import { GroupStateModel } from '../group/group-state';
import { memberName } from '../group/members';

type MaybePromise<T> = T | Promise<T>;

export interface ControlsHandlers {
  onAdd: () => MaybePromise<void>;
  onRemove: (leaf: number) => MaybePromise<void>;
  onCommit: (leaf: number) => MaybePromise<void>;
  onSend: (leaf: number, text: string) => MaybePromise<void>;
}

export function renderMemberControls(state: GroupStateModel, handlers: ControlsHandlers): HTMLDivElement {
  const root = document.createElement('div');
  root.className = 'grid-list';

  const add = document.createElement('button');
  add.textContent = '➕ Add member';
  add.setAttribute('aria-label', 'Add a new member to the group');
  add.onclick = () => {
    void handlers.onAdd();
  };
  root.appendChild(add);

  for (const leaf of state.tree.leaves) {
    const blank = state.tree.nodes.get(leaf)?.blank === true;
    if (blank) continue; // skip removed/empty leaves — nothing to act on
    const row = document.createElement('div');
    row.className = 'row';
    const inputId = `msg-input-leaf-${leaf}`;
    const name = memberName(leaf);

    const label = document.createElement('label');
    label.textContent = `${name} · leaf ${leaf}`;
    label.htmlFor = inputId;
    label.className = 'leaf-label';

    const remove = document.createElement('button');
    remove.className = 'danger';
    remove.textContent = '✕ Remove';
    remove.setAttribute('aria-label', `Remove ${name} (leaf ${leaf}) from the group`);
    remove.onclick = () => {
      void handlers.onRemove(leaf);
    };

    const update = document.createElement('button');
    update.textContent = '🔄 Update';
    update.setAttribute('aria-label', `${name} rotates their keys: stages an Update proposal and commits it in one step for leaf ${leaf}`);
    update.title = 'Stages an Update proposal and immediately commits it (see “Proposal vs Commit” in Concepts). Only the Commit advances the epoch.';
    update.onclick = () => {
      void handlers.onCommit(leaf);
    };

    const input = document.createElement('input');
    input.type = 'text';
    input.id = inputId;
    input.placeholder = `message from ${name}...`;

    const send = document.createElement('button');
    send.textContent = '📤 Send';
    send.setAttribute('aria-label', `Send an encrypted message from ${name} (leaf ${leaf})`);
    send.onclick = () => {
      void Promise.resolve(handlers.onSend(leaf, input.value || `hello from ${name}`));
      input.value = '';
    };

    row.appendChild(label);
    row.appendChild(remove);
    row.appendChild(update);
    row.appendChild(input);
    row.appendChild(send);
    root.appendChild(row);
  }

  return root;
}
