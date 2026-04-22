import { TranscriptEntry } from '../group/group-state';

export function renderTranscriptPanel(entries: TranscriptEntry[]): HTMLDivElement {
  const root = document.createElement('div');
  root.className = 'transcript-list';

  for (const item of entries) {
    const row = document.createElement('article');
    row.className = 'transcript-item';
    const head = document.createElement('div');
    head.innerHTML = `<strong>${item.kind.toUpperCase()}</strong> • epoch ${item.epoch}${item.generation ? ` • gen ${item.generation}` : ''}${item.senderLeaf !== undefined ? ` • sender ${item.senderLeaf}` : ''}`;
    const body = document.createElement('div');
    body.textContent = `${item.summary}: ${item.detail}`;
    row.appendChild(head);
    row.appendChild(body);
    if (item.tag) {
      const tag = document.createElement('small');
      tag.textContent = `AEAD tag: ${item.tag}`;
      row.appendChild(tag);
    }
    root.appendChild(row);
  }

  return root;
}
