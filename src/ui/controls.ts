import { GroupStateModel } from '../group/group-state';

type MaybePromise<T> = T | Promise<T>;

export interface ControlsHandlers {
  onAdd: () => MaybePromise<void>;
  onRemove: (leaf: number) => MaybePromise<void>;
  onCommit: (leaf: number) => MaybePromise<void>;
  onSend: (leaf: number, text: string) => void;
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
    const row = document.createElement('div');
    row.className = 'row';

    const label = document.createElement('span');
    label.textContent = `Leaf ${leaf}`;

    const remove = document.createElement('button');
    remove.className = 'danger';
    remove.textContent = '✕ Remove';
    remove.setAttribute('aria-label', `Remove leaf ${leaf} from the group`);
    remove.onclick = () => {
      void handlers.onRemove(leaf);
    };

    const update = document.createElement('button');
    update.textContent = '🔄 Update';
    update.setAttribute('aria-label', `Update key material for leaf ${leaf}`);
    update.onclick = () => {
      void handlers.onCommit(leaf);
    };

    const input = document.createElement('input');
    input.type = 'text';
    input.placeholder = 'message content...';
    input.setAttribute('aria-label', `Message input for leaf ${leaf}`);

    const send = document.createElement('button');
    send.textContent = '📤 Send';
    send.setAttribute('aria-label', `Send message from leaf ${leaf}`);
    send.onclick = () => {
      handlers.onSend(leaf, input.value || `hello from ${leaf}`);
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
