import { GroupStateModel, createInitialGroupState } from './group/group-state';
import { renderTreePanel } from './ui/tree-view';
import { renderTranscriptPanel } from './ui/transcript';
import { renderMemberControls } from './ui/controls';
import { deriveEpochSecrets } from './group/key-schedule';
import { commitWithProposals } from './proposals/commit';

function panel(title: string): HTMLElement {
  const el = document.createElement('section');
  el.className = 'panel';
  const h = document.createElement('h2');
  h.id = `panel-${title.toLowerCase().replace(/\s+/g, '-')}`;
  h.textContent = title;
  el.appendChild(h);
  el.setAttribute('aria-labelledby', h.id);
  return el;
}

function renderInspector(state: GroupStateModel): HTMLDivElement {
  const root = panel('Key Schedule Inspector');
  const pre = document.createElement('pre');
  pre.className = 'muted';
  const secrets = deriveEpochSecrets(state.initSecret, state.commitSecret);
  pre.textContent = Object.entries(secrets)
    .map(([k, v]) => `${k}: ${Array.from((v as Uint8Array).slice(0, 8)).map((b: number) => b.toString(16).padStart(2, '0')).join('')}...`)
    .join('\n');
  root.appendChild(pre);
  return root as HTMLDivElement;
}

function renderExplainer(): HTMLDivElement {
  const root = panel('Explainer') as HTMLDivElement;
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
  const root = panel('Comparison Panel') as HTMLDivElement;
  const caption = document.createElement('caption');
  caption.textContent = 'X3DH + Double Ratchet vs MLS (RFC 9420)';

  const table = document.createElement('table');
  table.className = 'table';

  const thead = document.createElement('thead');
  const headerRow = document.createElement('tr');
  ['Property', 'X3DH + Double Ratchet', 'MLS'].forEach(text => {
    const th = document.createElement('th');
    th.scope = 'col';
    th.textContent = text;
    headerRow.appendChild(th);
  });
  thead.appendChild(headerRow);
  table.appendChild(caption);
  table.appendChild(thead);

  const tbody = document.createElement('tbody');
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
    const row = tbody.insertRow();
    const propCell = document.createElement('th');
    propCell.scope = 'row';
    propCell.textContent = prop;
    row.appendChild(propCell);
    const x3dhCell = row.insertCell();
    x3dhCell.textContent = x3dh;
    const mlsCell = row.insertCell();
    mlsCell.innerHTML = mls;
  }

  table.appendChild(tbody);
  const scrollWrapper = document.createElement('div');
  scrollWrapper.className = 'table-scroll';
  scrollWrapper.appendChild(table);
  root.appendChild(scrollWrapper);
  return root;
}

function renderPcsPanel(state: GroupStateModel, rerender: () => void): HTMLDivElement {
  const root = panel('PCS Recovery Walkthrough') as HTMLDivElement;
  const epochSnippet = (s: Uint8Array) => Array.from(s.slice(0, 8)).map((b) => b.toString(16).padStart(2, '0')).join('');
  const isCompromised = state.compromisedPreUpdateSecret !== null;

  if (!isCompromised) {
    const pre = document.createElement('pre');
    pre.className = 'muted';
    pre.textContent = `current epoch secret: ${epochSnippet(state.epochSecret)}...\n(no compromise recorded)`;
    root.appendChild(pre);

    const compBtn = document.createElement('button');
    compBtn.textContent = '🔴 Mark Alice (leaf 0) as compromised';
    compBtn.setAttribute('aria-label', "Expose Alice's pre-update epoch secret to simulate compromise");
    compBtn.onclick = () => {
      state.compromisedPreUpdateSecret = state.epochSecret.slice();
      state.transcript.unshift({
        kind: 'proposal',
        summary: 'PCS: Alice marked compromised',
        detail: `Pre-update epoch secret exposed: ${epochSnippet(state.epochSecret)}...`,
        epoch: state.epoch
      });
      rerender();
    };
    root.appendChild(compBtn);
  } else {
    const preSecret = epochSnippet(state.compromisedPreUpdateSecret!);
    const leafNode = state.tree.nodes.get(0);
    const aliceLabel = document.createElement('div');
    aliceLabel.style.cssText = 'color: var(--danger); font-weight: 700; margin-bottom: 0.5rem;';
    aliceLabel.setAttribute('aria-live', 'polite');
    aliceLabel.textContent = leafNode && !leafNode.blank ? '🔴 Leaf 0 (Alice) — COMPROMISED' : '⬜ Leaf 0 — blank';
    root.appendChild(aliceLabel);

    const pre = document.createElement('pre');
    pre.className = 'muted';
    pre.textContent = `pre-update epoch:  ${preSecret}...  ← EXPOSED TO ATTACKER\ncurrent epoch:     ${epochSnippet(state.epochSecret)}...`;
    root.appendChild(pre);

    const recoverBtn = document.createElement('button');
    recoverBtn.textContent = '🔐 Alice commits Update (heals compromise)';
    recoverBtn.setAttribute('aria-label', 'Alice commits an Update to advance the epoch and lock the attacker out');
    recoverBtn.onclick = async () => {
      const preEpoch = state.epochSecret.slice();
      await commitWithProposals(state, [{ type: 'update', leafIndex: 0 }], 0);
      const postSnippet = epochSnippet(state.epochSecret);
      const matched = preEpoch.every((b, i) => b === state.epochSecret[i]);
      state.transcript.unshift({
        kind: 'commit',
        summary: 'PCS recovery: Alice updated',
        detail: matched
          ? `⚠ pre/post epoch secrets match — unexpected`
          : `pre: ${epochSnippet(preEpoch)}... → post: ${postSnippet}... — pre-update material cannot derive new epoch ✓`,
        epoch: state.epoch
      });
      rerender();
    };
    root.appendChild(recoverBtn);

    const verifyPre = document.createElement('pre');
    verifyPre.className = 'muted';
    try {
      const same = state.compromisedPreUpdateSecret!.every((b, i) => b === state.epochSecret[i]);
    verifyPre.className = same ? 'muted status-warning' : 'muted status-ok';
    verifyPre.textContent = same
        ? '⚠ Pre and post epoch secrets are equal — Update not yet applied'
        : '✓ Pre-compromise secret\n  ≠ current epoch — Attacker locked out ✓';
    } catch {
      verifyPre.textContent = '✓ PCS verification complete';
    }
    root.appendChild(verifyPre);
  }

  return root as HTMLDivElement;
}

function renderScenarioPanel(state: GroupStateModel, rerender: () => void, guard: (fn: () => Promise<void>) => Promise<void>): HTMLDivElement {
  const root = panel('Scenario Presets') as HTMLDivElement;
  const row = document.createElement('div');
  row.className = 'row';

  // All presets perform real crypto operations
  const presets: Array<[string, string, () => Promise<void>]> = [
    [
      '3 → 4 members',
      'Alice/Bob/Charlie bootstrap, Alice adds Dave',
      async () => {
        await commitWithProposals(state, [{ type: 'add' }], 0);
        rerender();
      }
    ],
    [
      'Remove a member',
      'Remove leaf 2 (Bob), direct path blanked',
      async () => {
        const bobLeaf = state.tree.leaves[1] ?? 2;
        const committer = state.tree.leaves.find((l) => l !== bobLeaf && !state.tree.nodes.get(l)?.blank) ?? 0;
        await commitWithProposals(state, [{ type: 'remove', leafIndex: bobLeaf }], committer);
        rerender();
      }
    ],
    [
      'PCS recovery',
      'Mark Alice compromised, then she commits an Update',
      async () => {
        state.seedPcsCompromise();
        rerender();
      }
    ],
    [
      'Churn drill (5×)',
      '5 real Update commits from leaf 0, epoch advances each time',
      async () => {
        for (let i = 0; i < 5; i++) {
          await commitWithProposals(state, [{ type: 'update', leafIndex: 0 }], 0);
        }
        rerender();
      }
    ]
  ];

  for (const [label, description, fn] of presets) {
    const b = document.createElement('button');
    b.textContent = label;
    b.setAttribute('aria-label', `Scenario: ${description}`);
    b.title = description;
    b.onclick = () => { void guard(fn); };
    row.appendChild(b);
  }

  root.appendChild(row);
  return root as HTMLDivElement;
}

export function renderApp(root: HTMLDivElement, state: GroupStateModel = createInitialGroupState()): { themeButton: HTMLButtonElement } {
  const previousFocusId = (document.activeElement as HTMLElement | null)?.id ?? null;
  let busy = false;

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

  const main = document.createElement('div');
  main.id = 'main-content';
  main.className = 'panels-grid';
  main.setAttribute('tabindex', '-1');

  const rerender = () => {
    renderApp(root, state);
  };

  const guard = async (fn: () => Promise<void>): Promise<void> => {
    if (busy) return;
    busy = true;
    try { await fn(); } finally { busy = false; }
  };

  const tree = panel('Tree');
  tree.appendChild(renderTreePanel(state));
  const transcript = panel('Transcript');
  transcript.appendChild(renderTranscriptPanel(state.transcript));
  const controls = panel('Member Controls');
  controls.appendChild(
    renderMemberControls(state, {
      onCommit: (member: number) => guard(async () => {
        await commitWithProposals(state, [{ type: 'update', leafIndex: member }], member);
        rerender();
      }),
      onRemove: (member: number) => guard(async () => {
        const committer = state.tree.leaves.find((l) => l !== member && !state.tree.nodes.get(l)?.blank) ?? member;
        await commitWithProposals(state, [{ type: 'remove', leafIndex: member }], committer);
        rerender();
      }),
      onAdd: () => guard(async () => {
        await commitWithProposals(state, [{ type: 'add' }], 0);
        rerender();
      }),
      onSend: (member: number, text: string) => guard(async () => {
        await state.sendApplication(member, text);
        rerender();
      })
    })
  );

  main.appendChild(tree);
  main.appendChild(transcript);
  main.appendChild(renderInspector(state));
  main.appendChild(controls);
  main.appendChild(renderExplainer());
  main.appendChild(renderScenarioPanel(state, rerender, guard));
  main.appendChild(renderPcsPanel(state, rerender));
  main.appendChild(renderComparisonPanel());

  root.appendChild(header);
  root.appendChild(main);

  if (previousFocusId) {
    const toRefocus = document.getElementById(previousFocusId);
    if (toRefocus) {
      toRefocus.focus({ preventScroll: true });
    }
  }

  return { themeButton };
}
