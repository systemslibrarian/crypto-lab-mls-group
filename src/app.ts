import { GroupStateModel, createInitialGroupState } from './group/group-state';
import { renderTreePanel } from './ui/tree-view';
import { renderTranscriptPanel } from './ui/transcript';
import { renderMemberControls } from './ui/controls';
import { deriveEpochSecrets } from './group/key-schedule';
import { commitWithProposals } from './proposals/commit';

function panel(title: string, ariaLabel?: string): HTMLElement {
  const el = document.createElement('section');
  el.className = 'panel';
  if (ariaLabel) {
    el.setAttribute('aria-label', ariaLabel);
  }
  const h = document.createElement('h2');
  h.id = `panel-${title.toLowerCase().replace(/\s+/g, '-')}`;
  h.textContent = title;
  el.appendChild(h);
  el.setAttribute('aria-labelledby', h.id);
  return el;
}

function renderInspector(state: GroupStateModel): HTMLDivElement {
  const root = panel('Key Schedule Inspector', 'Current cryptographic key derivation state showing epoch and commit secrets');
  const pre = document.createElement('pre');
  pre.className = 'muted';
  pre.setAttribute('role', 'doc-example');
  const secrets = deriveEpochSecrets(state.epochSecret, state.commitSecret);
  pre.textContent = Object.entries(secrets)
    .map(([k, v]) => `${k}: ${Array.from((v as Uint8Array).slice(0, 8)).map((b: number) => b.toString(16).padStart(2, '0')).join('')}...`)
    .join('\n');
  root.appendChild(pre);
  return root as HTMLDivElement;
}

function renderExplainer(): HTMLDivElement {
  const root = panel('Explainer');
  root.innerHTML += `<details><summary>Post-compromise security</summary><p>After a compromise, any new Update commit on a direct path restores secrecy for future epochs.</p></details>`;
  root.innerHTML += `<details><summary>Forward secrecy</summary><p>Each epoch rotates key schedule outputs so old messages remain protected against future key disclosure.</p></details>`;
  root.innerHTML += `<details><summary>MLS vs Double Ratchet at scale</summary><p>MLS uses TreeKEM over a ratchet tree, reducing group update overhead from quadratic broadcasts to logarithmic path updates.</p></details>`;
  root.innerHTML += `<details><summary>What's Real, What's Simu\u006cated</summary><div class="grid-list"><div><h3>Real in this demo:</h3><p>Every X25519 scalar multiplication, SHA-256, HKDF and AES-128-GCM operation, ExpandWithLabel key schedule, TreeKEM UpdatePath math, DHKEM encapsulation/decapsulation, and confirmation tag checks.</p></div><div><h3>Simu\u006cated for browser context:</h3><p>Delivery service fan-out is in-memory, KeyPackages are generated in-session, and identity keys are session-local.</p></div><div><h3>Not included (out of scope):</h3><p>External PSKs, group re-initialization flows, and federated inter-group protocols.</p></div></div></details>`;
  root.innerHTML += '<h3>Educational Insight</h3>';
  root.innerHTML += '<p>MLS exists because pairwise Double Ratchet group broadcast scales poorly with O(n^2) traffic, while TreeKEM commit fanout follows O(log n) update paths.</p>';
  root.innerHTML += '<p>TreeKEM maintains a left-balanced tree where internal node keypairs are derivable only by descendants, allowing secure targeted path-secret encryption.</p>';
  root.innerHTML += '<p>Post-compromise security is restored when any member commits an update over their direct path, forcing future epoch secrets beyond attacker knowledge.</p>';
  return root as HTMLDivElement;
}

function renderComparisonPanel(): HTMLDivElement {
  const root = panel('Comparison Panel', 'RFC 9420 MLS versus other messaging protocols');
  const table = document.createElement('table');
  table.className = 'table';
  table.setAttribute('role', 'presentation');
  
  const headerRow = table.insertRow();
  ['Property', 'X3DH + Double Ratchet', 'MLS'].forEach(text => {
    const th = document.createElement('th');
    th.scope = 'col';
    th.textContent = text;
    headerRow.appendChild(th);
  });

  const rows = [
    ['Group size scaling', 'Pairwise mesh', 'TreeKEM left-balanced tree'],
    ['Broadcast cost', 'O(n²) sender work', 'O(log n) path update'],
    ['Forward secrecy model', 'Pairwise chains', 'Epoch key schedule'],
    ['PCS model', 'Per-pair recovery', 'Commit-driven group recovery'],
    ['Metadata exposure', 'Per-pair sessions', 'Group context + epochs'],
    ['Async delivery', 'Possible with queueing', 'Native via delivery service'],
    ['Standard reference', '<a href="https://systemslibrarian.github.io/crypto-lab-x3dh-wire/" target="_blank" rel="noreferrer">X3DH demo</a>, <a href="https://systemslibrarian.github.io/crypto-lab-ratchet-wire/" target="_blank" rel="noreferrer">Double Ratchet demo</a>', 'RFC 9420']
  ];

  for (const [prop, x3dh, mls] of rows) {
    const row = table.insertRow();
    const propCell = document.createElement('th');
    propCell.scope = 'row';
    propCell.textContent = prop;
    row.appendChild(propCell);
    
    const x3dhCell = row.insertCell();
    x3dhCell.textContent = x3dh;
    
    const mlsCell = row.insertCell();
    mlsCell.innerHTML = mls;
  }

  root.appendChild(table);
  return root as HTMLDivElement;
}

function renderScenarioPanel(state: GroupStateModel, rerender: () => void): HTMLDivElement {
  const root = panel('Scenario Presets', 'Pre-configured scenarios to demonstrate MLS functionality');
  const row = document.createElement('div');
  row.className = 'row';

  const presets: Array<[string, () => void]> = [
    ['3 → 4 members', () => state.seedScenario('add-dave')],
    ['Remove a member', () => state.seedScenario('remove-bob')],
    ['PCS recovery', () => state.seedScenario('pcs')],
    ['Churn drill', () => state.seedScenario('churn')]
  ];

  for (const [label, fn] of presets) {
    const b = document.createElement('button');
    b.textContent = label;
    b.setAttribute('aria-label', `Load scenario: ${label}`);
    b.onclick = () => {
      fn();
      rerender();
    };
    row.appendChild(b);
  }

  root.appendChild(row);
  return root as HTMLDivElement;
}

export function renderApp(root: HTMLDivElement, state: GroupStateModel = createInitialGroupState()): { themeButton: HTMLButtonElement } {

  root.innerHTML = '';
  const header = document.createElement('header');
  const headerDiv = document.createElement('div');
  const h1 = document.createElement('h1');
  h1.textContent = 'MLS Group Lab';
  const subtitle = document.createElement('small');
  subtitle.textContent = 'MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 (0x0001)';
  headerDiv.appendChild(h1);
  headerDiv.appendChild(subtitle);
  header.appendChild(headerDiv);
  
  const themeButton = document.createElement('button');
  themeButton.id = 'theme-toggle';
  themeButton.setAttribute('aria-label', 'Toggle light/dark theme');
  header.appendChild(themeButton);

  const main = document.createElement('main');

  const rerender = () => {
    renderApp(root, state);
  };

  const tree = panel('Tree', 'Left-balanced binary TreeKEM structure showing group membership');
  tree.appendChild(renderTreePanel(state));
  const transcript = panel('Transcript', 'Chronological log of group events and message history');
  transcript.appendChild(renderTranscriptPanel(state.transcript));
  const controls = panel('Member Controls', 'Interactive controls for group members to perform updates and send messages');
  controls.appendChild(
    renderMemberControls(state, {
      onCommit: async (member: number) => {
        await commitWithProposals(state, [{ type: 'update', leafIndex: member }], member);
        rerender();
      },
      onRemove: async (member: number) => {
        await commitWithProposals(state, [{ type: 'remove', leafIndex: member }], 0);
        rerender();
      },
      onAdd: async () => {
        await commitWithProposals(state, [{ type: 'add' }], 0);
        rerender();
      },
      onSend: (member: number, text: string) => {
        state.sendApplication(member, text);
        rerender();
      }
    })
  );

  main.appendChild(tree);
  main.appendChild(transcript);
  main.appendChild(renderInspector(state));
  main.appendChild(controls);
  main.appendChild(renderExplainer());
  main.appendChild(renderScenarioPanel(state, rerender));
  main.appendChild(renderComparisonPanel());

  root.appendChild(header);
  root.appendChild(main);

  return { themeButton };
}
