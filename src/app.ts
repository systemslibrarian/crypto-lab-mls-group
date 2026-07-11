import { GroupStateModel, createInitialGroupState, Narration } from './group/group-state';
import { renderTreePanel } from './ui/tree-view';
import { renderTranscriptPanel } from './ui/transcript';
import { renderMemberControls } from './ui/controls';
import { commitWithProposals } from './proposals/commit';
import { memberName } from './group/members';
import { deriveConvergence } from './tree/treekem';
import { expandWithLabel } from './crypto/hkdf';
import { randomBytes, u16be, utf8 } from './crypto/ciphersuite';

// ── small helpers ──────────────────────────────────────────────────────────
const snip = (b: Uint8Array, n = 8): string =>
  Array.from(b.slice(0, n)).map((x) => x.toString(16).padStart(2, '0')).join('');

// Deterministic per-message key + nonce for a leaf from an encryption_secret,
// derived exactly as the real sender ratchet does. Deterministic so a legitimate
// recipient (same epoch secret) reproduces the key, while a removed member (stale
// secret) cannot — that's what the access-control demo shows.
function demoKeyNonce(encryptionSecret: Uint8Array, leaf: number): { key: Uint8Array; nonce: Uint8Array } {
  const leafSecret = expandWithLabel(encryptionSecret, 'secret', u16be(leaf), 32);
  return {
    key: expandWithLabel(leafSecret, 'key', new Uint8Array(), 16),
    nonce: expandWithLabel(leafSecret, 'nonce', new Uint8Array(), 12)
  };
}
const DEMO_AAD = utf8('mls-demo-app');

async function demoSeal(encryptionSecret: Uint8Array, leaf: number, plaintext: string): Promise<Uint8Array> {
  const { key, nonce } = demoKeyNonce(encryptionSecret, leaf);
  const k = await crypto.subtle.importKey('raw', key, 'AES-GCM', false, ['encrypt']);
  return new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: DEMO_AAD }, k, utf8(plaintext)));
}

// Returns the decrypted text, or null if AEAD authentication fails.
async function demoOpen(encryptionSecret: Uint8Array, senderLeaf: number, ciphertext: Uint8Array): Promise<string | null> {
  const { key, nonce } = demoKeyNonce(encryptionSecret, senderLeaf);
  try {
    const k = await crypto.subtle.importKey('raw', key, 'AES-GCM', false, ['decrypt']);
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce, additionalData: DEMO_AAD }, k, ciphertext);
    return new TextDecoder().decode(pt);
  } catch {
    return null;
  }
}

// First message key for a leaf in a given epoch, derived exactly as the sender
// ratchet does (encryption_secret → per-leaf secret → key). Used by the
// forward-secrecy demo to show the same derivation yields a different key once
// the epoch advances.
function leafMessageKeyHex(encryptionSecret: Uint8Array, leaf: number): string {
  const leafSecret = expandWithLabel(encryptionSecret, 'secret', u16be(leaf), 32);
  const key = expandWithLabel(leafSecret, 'key', new Uint8Array(), 16);
  return snip(key, 16);
}

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

// ── narration builders: plain-English "what just happened" ──────────────────
function buildAddNarration(state: GroupStateModel, addedLeaf: number | undefined, prevEpoch: number): Narration {
  const name = addedLeaf !== undefined ? memberName(addedLeaf) : 'A new member';
  return {
    headline: `${name} joined the group`,
    tone: 'success',
    lines: [
      `A leaf was allocated${addedLeaf !== undefined ? ` (leaf ${addedLeaf})` : ''} and ${name}'s KeyPackage installed there.`,
      `${memberName(0)} committed the change, so the epoch advanced ${prevEpoch} → ${state.epoch} and every member re-derived the new epoch secret.`,
      `${name} receives a Welcome carrying the current group secrets — they can read new messages but cannot recover anything sent before they joined.`
    ]
  };
}

function buildRemoveNarration(state: GroupStateModel, removedLeaf: number, committerLeaf: number, prevEpoch: number): Narration {
  return {
    headline: `${memberName(removedLeaf)} was removed`,
    tone: 'danger',
    lines: [
      `Leaf ${removedLeaf} and every node on its direct path were blanked, erasing the keys ${memberName(removedLeaf)} held.`,
      `${memberName(committerLeaf)} committed a fresh path over the gap, so the surviving members share brand-new key material.`,
      `Epoch ${prevEpoch} → ${state.epoch}: the new epoch secret is unknowable to ${memberName(removedLeaf)}, so they cannot read anything sent from now on.`
    ]
  };
}

function buildUpdateNarration(state: GroupStateModel, leaf: number, prevEpoch: number): Narration {
  const path = state.tree.directPath(leaf);
  return {
    headline: `${memberName(leaf)} rotated their keys (Update)`,
    tone: 'success',
    lines: [
      `${memberName(leaf)} chose a new path secret and pushed fresh keys up their direct path: node${path.length === 1 ? '' : 's'} ${path.join(', ') || '(root only)'}.`,
      `Each new node key is encrypted only to its copath subtree, so just the right members can derive it — O(log n) work, not an O(n) broadcast.`,
      `Epoch ${prevEpoch} → ${state.epoch}. Had ${memberName(leaf)} been compromised before this, the attacker is now locked out: that's post-compromise security.`
    ]
  };
}

function buildSendNarration(state: GroupStateModel, leaf: number, gen: number): Narration {
  return {
    headline: `${memberName(leaf)} sent an encrypted message`,
    tone: 'info',
    lines: [
      `Sealed with AES-128-GCM under a one-time key from ${memberName(leaf)}'s sender ratchet (generation ${gen}).`,
      `The ratchet then advances and discards that key — so this exact message can never be decrypted again, even by ${memberName(leaf)}. That's forward secrecy.`,
      `The AEAD's associated data binds the ciphertext to epoch ${state.epoch}, generation ${gen}, and sender leaf ${leaf}, so it can't be replayed into another context.`
    ]
  };
}

// ── status banner (full width) ──────────────────────────────────────────────
function renderStatusBanner(state: GroupStateModel, animate: boolean, rerender: () => void, guard: (fn: () => Promise<void>) => Promise<void>): HTMLElement {
  const banner = document.createElement('section');
  banner.className = 'status-banner';
  banner.setAttribute('aria-label', 'Group status');

  const members = state.activeMembers();
  const names = members.map(memberName).join(', ');

  const stat = (label: string, value: string, valueClass = '') => {
    const d = document.createElement('div');
    d.className = 'stat';
    d.innerHTML = `<span class="stat-label">${label}</span><span class="stat-value ${valueClass}">${value}</span>`;
    return d;
  };

  banner.appendChild(stat('Epoch', `${state.epoch}`, animate ? 'epoch-bump' : ''));
  banner.appendChild(stat(`Members (${members.length})`, names || '—'));
  banner.appendChild(stat('Ciphersuite', 'MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519 (0x0001)'));

  if (!state.tour.active) {
    const tourBtn = document.createElement('button');
    tourBtn.className = 'tour-start';
    tourBtn.textContent = '🧭 Start guided tour';
    tourBtn.setAttribute('aria-label', 'Start the guided tour of the MLS group lifecycle');
    tourBtn.onclick = () => void guard(async () => { state.tour = { active: true, step: 0 }; rerender(); });
    banner.appendChild(tourBtn);
  }

  return banner;
}

// ── "what just happened" narration (full width) ─────────────────────────────
function renderNarration(state: GroupStateModel): HTMLElement {
  const n: Narration = state.narration ?? {
    headline: 'Welcome — this is a live MLS group',
    tone: 'info',
    lines: [
      `The group starts with ${state.activeMembers().map(memberName).join(', ')}. Every key below is real: X25519, HKDF-SHA256, AES-128-GCM.`,
      'Try this: send a message, then have someone press Update and watch the tree re-key and the epoch advance.',
      'This box narrates each action in plain English; the Transcript keeps the full protocol log.'
    ]
  };

  const root = document.createElement('section');
  root.className = `narration narration-${n.tone}`;
  root.setAttribute('aria-label', 'What just happened');
  root.setAttribute('aria-live', 'polite');

  const h = document.createElement('h2');
  h.className = 'narration-headline';
  h.textContent = n.headline;
  root.appendChild(h);

  const ul = document.createElement('ul');
  for (const line of n.lines) {
    const li = document.createElement('li');
    li.textContent = line;
    ul.appendChild(li);
  }
  root.appendChild(ul);
  return root;
}

// ── key-schedule derivation diagram ─────────────────────────────────────────
function renderKeySchedule(state: GroupStateModel): HTMLDivElement {
  const root = panel('Key Schedule') as HTMLDivElement;

  const intro = document.createElement('p');
  intro.className = 'muted';
  intro.textContent =
    'Two inputs seed each epoch: init_secret carried from the previous epoch, and commit_secret from this commit’s TreeKEM path. Mixing both is what delivers forward secrecy and post-compromise security. Showing first 8 bytes of each.';
  root.appendChild(intro);

  const s = state.epochSecrets;
  const flow = document.createElement('div');
  flow.className = 'ks-flow';

  const chip = (name: string, value: Uint8Array, kind: string): HTMLElement => {
    const c = document.createElement('div');
    c.className = `ks-chip ks-${kind}`;
    c.innerHTML = `<span class="ks-name">${name}</span><span class="ks-hex">${snip(value)}…</span>`;
    return c;
  };
  const arrow = (text: string): HTMLElement => {
    const a = document.createElement('div');
    a.className = 'ks-arrow';
    a.innerHTML = `<span class="ks-op">${text}</span>`;
    return a;
  };
  const rowOf = (...els: HTMLElement[]): HTMLElement => {
    const r = document.createElement('div');
    r.className = 'ks-row';
    els.forEach((e) => r.appendChild(e));
    return r;
  };

  // inputs → joiner → epoch → leaf secrets
  flow.appendChild(rowOf(chip('init_secret', state.epochInputs.init, 'input'), chip('commit_secret', state.epochInputs.commit, 'input')));
  flow.appendChild(arrow('Extract(init_secret, commit_secret)'));
  flow.appendChild(rowOf(chip('joiner_secret', s.joiner, 'mid'), chip('welcome_secret', s.welcome, 'mid')));
  flow.appendChild(arrow('DeriveSecret(joiner_secret, "epoch")'));
  flow.appendChild(rowOf(chip('epoch_secret', s.epoch, 'epoch')));
  flow.appendChild(arrow('DeriveSecret(epoch_secret, label) — one per label'));
  flow.appendChild(rowOf(
    chip('sender_data', s.sender_data, 'leaf'),
    chip('encryption', s.encryption, 'leaf'),
    chip('exporter', s.exporter, 'leaf'),
    chip('external', s.external, 'leaf'),
    chip('confirmation', s.confirmation, 'leaf'),
    chip('membership', s.membership, 'leaf'),
    chip('resumption', s.resumption, 'leaf'),
    chip('authentication', s.authentication, 'leaf'),
    chip('init (next epoch)', s.init, 'leaf')
  ));

  root.appendChild(flow);
  return root;
}

// ── forward-secrecy walkthrough ─────────────────────────────────────────────
function renderFsPanel(state: GroupStateModel, rerender: () => void, guard: (fn: () => Promise<void>) => Promise<void>): HTMLDivElement {
  const root = panel('Forward Secrecy Walkthrough') as HTMLDivElement;
  const intro = document.createElement('p');
  intro.className = 'muted';
  intro.textContent =
    'Forward secrecy means a key stolen today cannot unlock yesterday’s messages. Capture a message key, advance the epoch, and watch the same derivation produce a different key — the old one is gone.';
  root.appendChild(intro);

  const snap = state.fsSnapshot;

  // Step 1 — capture
  if (!snap) {
    const leaf = state.activeMembers()[0] ?? 0;
    const btn = document.createElement('button');
    btn.textContent = `📨 Capture ${memberName(leaf)}'s current message key`;
    btn.setAttribute('aria-label', `Record the message key ${memberName(leaf)} would use right now, in epoch ${state.epoch}`);
    btn.onclick = () => void guard(async () => {
      const encSecret = state.epochSecrets.encryption;
      state.fsSnapshot = {
        epoch: state.epoch,
        leaf,
        encHex: snip(encSecret),
        msgKeyHex: leafMessageKeyHex(encSecret, leaf)
      };
      state.transcript.unshift({
        kind: 'application',
        summary: `FS demo: captured ${memberName(leaf)}'s message key`,
        detail: `epoch ${state.epoch} message key recorded for comparison`,
        epoch: state.epoch
      });
      rerender();
    });
    root.appendChild(btn);
    return root;
  }

  // Captured state — always show the recorded key
  const captured = document.createElement('pre');
  captured.className = 'muted';
  captured.textContent =
    `captured in epoch ${snap.epoch} (${memberName(snap.leaf)}):\n` +
    `  encryption_secret: ${snap.encHex}…\n` +
    `  message key:       ${snap.msgKeyHex}`;
  root.appendChild(captured);

  if (snap.epoch === state.epoch) {
    // Step 2 — advance the epoch
    const note = document.createElement('p');
    note.className = 'muted';
    note.textContent = 'Now advance the epoch. Any commit reseeds every sender ratchet from a fresh encryption_secret.';
    root.appendChild(note);

    const advance = document.createElement('button');
    advance.textContent = '⏭ Advance one epoch (commit an Update)';
    advance.setAttribute('aria-label', 'Have a member commit an Update so the epoch advances');
    advance.onclick = () => void guard(async () => {
      const committer = state.activeMembers()[0] ?? 0;
      await commitWithProposals(state, [{ type: 'update', leafIndex: committer }], committer);
      rerender();
    });
    root.appendChild(advance);
  } else {
    // Step 3 — verdict: same derivation now yields a different key
    const nowHex = leafMessageKeyHex(state.epochSecrets.encryption, snap.leaf);
    const differs = nowHex !== snap.msgKeyHex;

    const compare = document.createElement('pre');
    compare.className = differs ? 'muted status-ok' : 'muted status-warning';
    compare.textContent =
      `same derivation, now in epoch ${state.epoch}:\n` +
      `  message key:       ${nowHex}\n\n` +
      (differs
        ? `✓ Different key — the epoch-${snap.epoch} key cannot be reproduced\n  from any current secret. Past messages stay locked.`
        : '⚠ keys match — unexpected');
    root.appendChild(compare);

    const reset = document.createElement('button');
    reset.textContent = '↺ Reset forward-secrecy demo';
    reset.setAttribute('aria-label', 'Clear the captured key and start the forward-secrecy demo over');
    reset.onclick = () => void guard(async () => {
      state.fsSnapshot = null;
      rerender();
    });
    root.appendChild(reset);
  }

  return root;
}

function renderExplainer(): HTMLDivElement {
  const root = panel('Concepts') as HTMLDivElement;
  root.innerHTML += `<details><summary>Forward secrecy</summary><p>Each epoch derives a fresh key schedule and reseeds every sender ratchet, and each message key is discarded after one use. A key compromised today cannot decrypt earlier messages. See the Forward Secrecy Walkthrough to try it.</p></details>`;
  root.innerHTML += `<details><summary>Post-compromise security</summary><p>After a member is compromised, any new Update commit on their direct path replaces the leaked keys, so future epochs are secret again. See the PCS Recovery Walkthrough.</p></details>`;
  root.innerHTML += `<details><summary>Why a tree? MLS vs Double Ratchet at scale</summary><p>Pairwise Double Ratchet needs O(n²) messages to re-key a group. TreeKEM arranges members as leaves of a left-balanced binary tree, so a re-key only touches one root-to-leaf direct path — O(log n) ciphertexts per commit.</p></details>`;
  root.innerHTML += `<details><summary>What's Real, What's Simulated</summary><div class="grid-list"><div><h3>Real in this demo:</h3><p>Every X25519 scalar multiplication, SHA-256, HKDF and AES-128-GCM operation, ExpandWithLabel key schedule, TreeKEM UpdatePath math, DHKEM encapsulation/decapsulation, and confirmation tag checks.</p></div><div><h3>Simulated for browser context:</h3><p>Delivery service fan-out is in-memory, KeyPackages are generated in-session, and identity keys are session-local.</p></div><div><h3>Not included (out of scope):</h3><p>External PSKs, group re-initialization flows, and federated inter-group protocols.</p></div></div></details>`;
  return root;
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

function renderPcsPanel(state: GroupStateModel, rerender: () => void, guard: (fn: () => Promise<void>) => Promise<void>): HTMLDivElement {
  const root = panel('PCS Recovery Walkthrough') as HTMLDivElement;
  const intro = document.createElement('p');
  intro.className = 'muted';
  intro.textContent =
    'Post-compromise security means that even after an attacker steals a member’s keys, one fresh Update from that member locks the attacker back out.';
  root.appendChild(intro);

  const aliceName = memberName(0);
  const isCompromised = state.compromisedPreUpdateSecret !== null;

  if (!isCompromised) {
    const pre = document.createElement('pre');
    pre.className = 'muted';
    pre.textContent = `current epoch secret: ${snip(state.epochSecret)}...\n(no compromise recorded)`;
    root.appendChild(pre);

    const compBtn = document.createElement('button');
    compBtn.textContent = `🔴 Mark ${aliceName} (leaf 0) as compromised`;
    compBtn.setAttribute('aria-label', `Expose ${aliceName}'s pre-update epoch secret to simulate compromise`);
    compBtn.onclick = () => void guard(async () => {
      state.compromisedPreUpdateSecret = state.epochSecret.slice();
      state.transcript.unshift({
        kind: 'proposal',
        summary: `PCS: ${aliceName} marked compromised`,
        detail: `Pre-update epoch secret exposed: ${snip(state.epochSecret)}...`,
        epoch: state.epoch
      });
      rerender();
    });
    root.appendChild(compBtn);
  } else {
    const preSecret = snip(state.compromisedPreUpdateSecret!);
    const leafNode = state.tree.nodes.get(0);
    const aliceLabel = document.createElement('div');
    aliceLabel.style.cssText = 'color: var(--danger); font-weight: 700; margin-bottom: 0.5rem;';
    aliceLabel.setAttribute('aria-live', 'polite');
    aliceLabel.textContent = leafNode && !leafNode.blank ? `🔴 ${aliceName} (leaf 0) — COMPROMISED` : '⬜ Leaf 0 — blank';
    root.appendChild(aliceLabel);

    const pre = document.createElement('pre');
    pre.className = 'muted';
    pre.textContent = `pre-update epoch:  ${preSecret}...  ← EXPOSED TO ATTACKER\ncurrent epoch:     ${snip(state.epochSecret)}...`;
    root.appendChild(pre);

    const recoverBtn = document.createElement('button');
    recoverBtn.textContent = `🔐 ${aliceName} commits Update (heals compromise)`;
    recoverBtn.setAttribute('aria-label', `${aliceName} commits an Update to advance the epoch and lock the attacker out`);
    recoverBtn.onclick = () => void guard(async () => {
      const preEpoch = state.epochSecret.slice();
      await commitWithProposals(state, [{ type: 'update', leafIndex: 0 }], 0);
      const postSnippet = snip(state.epochSecret);
      const matched = preEpoch.every((b, i) => b === state.epochSecret[i]);
      state.transcript.unshift({
        kind: 'commit',
        summary: `PCS recovery: ${aliceName} updated`,
        detail: matched
          ? `⚠ pre/post epoch secrets match — unexpected`
          : `pre: ${snip(preEpoch)}... → post: ${postSnippet}... — pre-update material cannot derive new epoch ✓`,
        epoch: state.epoch
      });
      rerender();
    });
    root.appendChild(recoverBtn);

    const verifyPre = document.createElement('pre');
    const same = state.compromisedPreUpdateSecret!.every((b, i) => b === state.epochSecret[i]);
    verifyPre.className = same ? 'muted status-warning' : 'muted status-ok';
    verifyPre.textContent = same
      ? '⚠ Pre and post epoch secrets are equal — Update not yet applied'
      : '✓ Pre-compromise secret\n  ≠ current epoch — Attacker locked out ✓';
    root.appendChild(verifyPre);
  }

  return root;
}

function renderScenarioPanel(state: GroupStateModel, rerender: () => void, guard: (fn: () => Promise<void>) => Promise<void>): HTMLDivElement {
  const root = panel('Scenario Presets') as HTMLDivElement;
  const intro = document.createElement('p');
  intro.className = 'muted';
  intro.textContent = 'One-click stories. Each runs real commits; watch the tree, narration, and epoch update.';
  root.appendChild(intro);
  const row = document.createElement('div');
  row.className = 'row';

  const presets: Array<[string, string, () => Promise<void>]> = [
    [
      'Add a member',
      `${memberName(0)} adds the next member and commits`,
      async () => {
        const before = new Set(state.activeMembers());
        const prevEpoch = state.epoch;
        await commitWithProposals(state, [{ type: 'add' }], 0);
        const added = state.activeMembers().find((l) => !before.has(l));
        state.narration = buildAddNarration(state, added, prevEpoch);
        rerender();
      }
    ],
    [
      'Remove a member',
      `Remove ${memberName(2)} (leaf 2); their direct path is blanked and re-keyed`,
      async () => {
        const bobLeaf = state.tree.leaves[1] ?? 2;
        const committer = state.activeMembers().find((l) => l !== bobLeaf) ?? 0;
        const prevEpoch = state.epoch;
        await commitWithProposals(state, [{ type: 'remove', leafIndex: bobLeaf }], committer);
        state.narration = buildRemoveNarration(state, bobLeaf, committer, prevEpoch);
        rerender();
      }
    ],
    [
      'PCS recovery',
      `Mark ${memberName(0)} compromised, then she commits an Update`,
      async () => {
        state.seedPcsCompromise();
        state.narration = {
          headline: `${memberName(0)} is marked compromised`,
          tone: 'danger',
          lines: [
            `An attacker is assumed to hold ${memberName(0)}'s current keys, so the present epoch secret is exposed.`,
            `Use the PCS Recovery Walkthrough to have ${memberName(0)} commit an Update.`,
            'After that Update, the epoch secret changes and the attacker can no longer follow along — post-compromise security.'
          ]
        };
        rerender();
      }
    ],
    [
      'Churn drill (5×)',
      `5 real Update commits from ${memberName(0)}; the epoch advances each time`,
      async () => {
        const prevEpoch = state.epoch;
        for (let i = 0; i < 5; i++) {
          await commitWithProposals(state, [{ type: 'update', leafIndex: 0 }], 0);
        }
        state.narration = {
          headline: `${memberName(0)} ran 5 Update commits`,
          tone: 'info',
          lines: [
            `The epoch advanced ${prevEpoch} → ${state.epoch}; every commit rotated keys on ${memberName(0)}'s direct path.`,
            'Each step reseeds the whole key schedule, so message keys from earlier epochs are unrecoverable.',
            'This is what continuous re-keying ("churn") looks like in a busy group.'
          ]
        };
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
  return root;
}

// ── shared actions (used by panels and the guided tour) ─────────────────────
async function runConvergence(state: GroupStateModel): Promise<void> {
  const committerLeaf = state.lastCommitterLeaf ?? state.activeMembers()[0] ?? 0;
  const { committerSecret, rows } = await deriveConvergence(state.tree, committerLeaf, randomBytes(32));
  const target = snip(committerSecret);
  state.convergence = {
    committerLeaf,
    rows: rows.map((r) => ({
      leaf: r.leaf,
      isCommitter: r.isCommitter,
      viaDecrypt: r.viaDecrypt,
      hex: snip(r.secret),
      match: snip(r.secret) === target
    }))
  };
}

async function runAccess(state: GroupStateModel): Promise<void> {
  const snap = state.removedSnapshot;
  if (!snap) return;
  const active = state.activeMembers();
  const senderLeaf = active[0] ?? 0;
  const legitLeaf = active.find((l) => l !== senderLeaf) ?? senderLeaf;
  const plaintext = 'Meet at the safe house at 21:00.';
  const groupEnc = state.epochSecrets.encryption;

  const ct = await demoSeal(groupEnc, senderLeaf, plaintext);
  const legitText = await demoOpen(groupEnc, senderLeaf, ct); // current member: same epoch secret
  const removedText = await demoOpen(snap.encryptionSecret, senderLeaf, ct); // removed: stale secret

  state.accessResult = {
    epoch: state.epoch,
    senderLeaf,
    ctHex: snip(ct, 12),
    legitLeaf,
    legitText,
    removedLeaf: snap.leaf,
    removedText
  };
}

// ── TreeKEM convergence proof ───────────────────────────────────────────────
function renderConvergencePanel(state: GroupStateModel, rerender: () => void, guard: (fn: () => Promise<void>) => Promise<void>): HTMLDivElement {
  const root = panel('TreeKEM Convergence') as HTMLDivElement;
  const intro = document.createElement('p');
  intro.className = 'muted';
  intro.textContent =
    'The whole point of TreeKEM: after one member commits a path, every member ends up with the same root secret — the committer by ratcheting up their path, everyone else by decrypting just one path secret. Run it and compare.';
  root.appendChild(intro);

  const committerLeaf = state.lastCommitterLeaf ?? state.activeMembers()[0] ?? 0;
  const btn = document.createElement('button');
  btn.textContent = `▶ Derive root secret as each member (committer: ${memberName(committerLeaf)})`;
  btn.setAttribute('aria-label', `Independently derive the root secret for every member, with ${memberName(committerLeaf)} as committer`);
  btn.onclick = () => void guard(async () => { await runConvergence(state); rerender(); });
  root.appendChild(btn);

  const result = state.convergence;
  if (result) {
    const allMatch = result.rows.every((r) => r.match);
    const table = document.createElement('table');
    table.className = 'table conv-table';
    const thead = document.createElement('thead');
    thead.innerHTML = '<tr><th scope="col">Member</th><th scope="col">Derived via</th><th scope="col">Root secret</th><th scope="col">Agrees</th></tr>';
    table.appendChild(thead);
    const tbody = document.createElement('tbody');
    for (const r of result.rows) {
      const tr = document.createElement('tr');
      const via = r.isCommitter ? 'ratchet up own path' : (r.viaDecrypt ? 'HPKE-decrypt + ratchet' : 'direct (commit secret)');
      tr.innerHTML =
        `<th scope="row">${memberName(r.leaf)}</th>` +
        `<td>${via}</td>` +
        `<td><code>${r.hex}…</code></td>` +
        `<td>${r.match ? '✓' : '✗'}</td>`;
      tbody.appendChild(tr);
    }
    table.appendChild(tbody);
    const scroll = document.createElement('div');
    scroll.className = 'table-scroll';
    scroll.appendChild(table);
    root.appendChild(scroll);

    const verdict = document.createElement('pre');
    verdict.className = allMatch ? 'muted status-ok' : 'muted status-warning';
    verdict.textContent = allMatch
      ? `✓ All ${result.rows.length} members independently derived the same root secret.\n  That shared secret becomes the next epoch's commit_secret.`
      : '⚠ Secrets diverged — unexpected';
    root.appendChild(verdict);
  }

  return root;
}

// ── Access control: a removed member is locked out ──────────────────────────
function renderAccessPanel(state: GroupStateModel, rerender: () => void, guard: (fn: () => Promise<void>) => Promise<void>): HTMLDivElement {
  const root = panel('Access Control: Removed Member') as HTMLDivElement;
  const intro = document.createElement('p');
  intro.className = 'muted';
  intro.textContent =
    'Removing a member rotates the group keys. Here we prove it: the group sends a real AES-GCM message in the current epoch, a current member reads it, and the removed member — holding only their stale epoch secret — cannot.';
  root.appendChild(intro);

  if (!state.removedSnapshot) {
    const note = document.createElement('p');
    note.className = 'muted';
    note.textContent = 'No one has been removed yet. Remove a member (Member Controls, the “Remove a member” scenario, or the guided tour) to run this demo.';
    root.appendChild(note);
    return root;
  }

  const removedLeaf = state.removedSnapshot.leaf;
  const btn = document.createElement('button');
  btn.textContent = `▶ Send a secret in epoch ${state.epoch} and test access`;
  btn.setAttribute('aria-label', `Encrypt a message in the current epoch and try to read it as both a current member and the removed ${memberName(removedLeaf)}`);
  btn.onclick = () => void guard(async () => { await runAccess(state); rerender(); });
  root.appendChild(btn);

  const r = state.accessResult;
  if (r) {
    const out = document.createElement('pre');
    const lockedOut = r.removedText === null && r.legitText !== null;
    out.className = lockedOut ? 'muted status-ok' : 'muted status-warning';
    out.textContent =
      `${memberName(r.senderLeaf)} (epoch ${r.epoch}) sent: ${r.ctHex}… [ciphertext]\n\n` +
      `${memberName(r.legitLeaf)} (current member): ${r.legitText !== null ? `“${r.legitText}” ✓` : 'FAILED ✗'}\n` +
      `${memberName(r.removedLeaf)} (removed): ${r.removedText !== null ? `“${r.removedText}” ✗ should be locked out` : '🔒 AEAD authentication failed — locked out ✓'}`;
    root.appendChild(out);
  }

  return root;
}

// ── Guided tour ─────────────────────────────────────────────────────────────
interface TourStep { title: string; body: string; act: string | null; cta?: string; }
const TOUR: TourStep[] = [
  { title: 'Welcome to the MLS Group Lab', body: 'You are looking at a real end-to-end encrypted group. Every key below is computed with real X25519, HKDF-SHA256 and AES-128-GCM — nothing is faked. This tour walks through the whole group lifecycle in a few clicks.', act: null, cta: 'Begin ▶' },
  { title: 'Add a member', body: 'A new member is added and the change is committed. Watch the ratchet tree gain a leaf and the epoch advance. The newcomer gets a Welcome with the current secrets, but cannot read anything sent before they joined.', act: 'add', cta: 'Add & continue ▶' },
  { title: 'Send a message', body: 'A member sends an encrypted message, sealed under a one-time key from their sender ratchet. The ratchet then advances and discards that key — so this message can never be decrypted again. That is forward secrecy.', act: 'send', cta: 'Send & continue ▶' },
  { title: 'Re-key with an Update', body: 'A member runs an Update. Watch their direct path light up and climb to the root, and the epoch roll over. Only one root-to-leaf path changes — that is the O(log n) re-key at the heart of TreeKEM.', act: 'update', cta: 'Update & continue ▶' },
  { title: 'Everyone agrees on the new secret', body: 'That Update just ran the convergence proof below: every member independently arrived at the SAME root secret — the committer by ratcheting, the others by decrypting one path secret. Scroll to the TreeKEM Convergence panel to see the matching values.', act: 'converge', cta: 'Prove it & continue ▶' },
  { title: 'Remove a member', body: 'A member is removed. Their leaf and entire direct path are blanked, then re-keyed by the committer, so the keys they knew are now worthless to them.', act: 'remove', cta: 'Remove & continue ▶' },
  { title: 'The removed member is locked out', body: 'This just ran the access-control demo below: the group sent a fresh message and the removed member failed to decrypt it, while a current member succeeded. See the Access Control panel.', act: 'access', cta: 'Show lockout & continue ▶' },
  { title: 'Heal a compromise', body: 'Finally we simulate a compromise of a member and immediately heal it with an Update. After that commit the attacker is locked out of all future epochs — post-compromise security. See the PCS Recovery panel.', act: 'pcs', cta: 'Heal & continue ▶' },
  { title: 'That is the whole lifecycle', body: 'Add and remove members, send messages, watch epochs roll, and explore the live key schedule — all backed by real cryptography. Tour complete.', act: null, cta: 'Finish ✓' }
];

async function runTourAction(state: GroupStateModel, act: string): Promise<void> {
  const active = state.activeMembers();
  switch (act) {
    case 'add': {
      const before = new Set(state.activeMembers());
      const prevEpoch = state.epoch;
      await commitWithProposals(state, [{ type: 'add' }], 0);
      const added = state.activeMembers().find((l) => !before.has(l));
      state.narration = buildAddNarration(state, added, prevEpoch);
      break;
    }
    case 'send': {
      const sender = active[0] ?? 0;
      await state.sendApplication(sender, 'hello team — first encrypted message');
      const gen = state.ratchets.get(sender)?.appGeneration ?? 1;
      state.narration = buildSendNarration(state, sender, gen);
      break;
    }
    case 'update': {
      const committer = active.find((l) => l !== (active[0] ?? 0)) ?? active[0] ?? 0;
      const prevEpoch = state.epoch;
      await commitWithProposals(state, [{ type: 'update', leafIndex: committer }], committer);
      state.narration = buildUpdateNarration(state, committer, prevEpoch);
      await runConvergence(state);
      break;
    }
    case 'converge':
      await runConvergence(state);
      break;
    case 'remove': {
      // Remove the last member so the demo stays predictable.
      const victim = active[active.length - 1] ?? active[0] ?? 0;
      const committer = active.find((l) => l !== victim) ?? 0;
      const prevEpoch = state.epoch;
      state.removedSnapshot = { leaf: victim, epoch: state.epoch, encryptionSecret: state.epochSecrets.encryption.slice() };
      await commitWithProposals(state, [{ type: 'remove', leafIndex: victim }], committer);
      state.narration = buildRemoveNarration(state, victim, committer, prevEpoch);
      break;
    }
    case 'access':
      await runAccess(state);
      break;
    case 'pcs': {
      state.seedPcsCompromise();
      const prevEpoch = state.epoch;
      await commitWithProposals(state, [{ type: 'update', leafIndex: 0 }], 0);
      state.narration = {
        headline: `${memberName(0)} healed the compromise`,
        tone: 'success',
        lines: [
          `${memberName(0)} committed an Update, advancing the epoch ${prevEpoch} → ${state.epoch}.`,
          'The new epoch secret is derived from fresh path material the attacker never saw.',
          'Even though the attacker held the old keys, they are now locked out of every future epoch — post-compromise security.'
        ]
      };
      break;
    }
  }
}

function renderTour(state: GroupStateModel, rerender: () => void, guard: (fn: () => Promise<void>) => Promise<void>): HTMLElement {
  const step = TOUR[state.tour.step] ?? TOUR[0];
  const root = document.createElement('section');
  root.className = 'tour-card';
  root.setAttribute('aria-label', 'Guided tour');
  root.setAttribute('aria-live', 'polite');

  const meta = document.createElement('div');
  meta.className = 'tour-meta';
  meta.textContent = `Guided tour · step ${state.tour.step + 1} of ${TOUR.length}`;
  root.appendChild(meta);

  const h = document.createElement('h2');
  h.className = 'tour-title';
  h.textContent = step.title;
  root.appendChild(h);

  const body = document.createElement('p');
  body.className = 'tour-body';
  body.textContent = step.body;
  root.appendChild(body);

  const controls = document.createElement('div');
  controls.className = 'row tour-controls';

  const isLast = state.tour.step >= TOUR.length - 1;
  const next = document.createElement('button');
  next.textContent = step.cta ?? (isLast ? 'Finish ✓' : 'Next ▶');
  next.onclick = () => void guard(async () => {
    if (step.act) await runTourAction(state, step.act);
    if (isLast) {
      state.tour = { active: false, step: 0 };
    } else {
      state.tour = { active: true, step: state.tour.step + 1 };
    }
    rerender();
  });
  controls.appendChild(next);

  const skip = document.createElement('button');
  skip.textContent = 'Exit tour';
  skip.className = 'tour-skip';
  skip.setAttribute('aria-label', 'Exit the guided tour');
  skip.onclick = () => void guard(async () => { state.tour = { active: false, step: 0 }; rerender(); });
  controls.appendChild(skip);

  root.appendChild(controls);
  return root;
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
  subtitle.textContent = 'Interactive RFC 9420 TreeKEM — real X25519 · HKDF-SHA256 · AES-128-GCM';
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

  // Fire transition animations only when the epoch actually advanced this render.
  const animate = state.epoch !== state.animEpoch;
  state.animEpoch = state.epoch;

  const rerender = () => {
    renderApp(root, state);
  };

  const guard = async (fn: () => Promise<void>): Promise<void> => {
    if (busy) return;
    busy = true;
    try { await fn(); } finally { busy = false; }
  };

  const tree = panel('Ratchet Tree');
  tree.appendChild(renderTreePanel(state, animate));
  const transcript = panel('Transcript');
  transcript.appendChild(renderTranscriptPanel(state.transcript));
  const controls = panel('Member Controls');
  controls.appendChild(
    renderMemberControls(state, {
      onCommit: (member: number) => guard(async () => {
        const prevEpoch = state.epoch;
        await commitWithProposals(state, [{ type: 'update', leafIndex: member }], member);
        state.narration = buildUpdateNarration(state, member, prevEpoch);
        rerender();
      }),
      onRemove: (member: number) => guard(async () => {
        const committer = state.activeMembers().find((l) => l !== member) ?? member;
        const prevEpoch = state.epoch;
        // Capture the epoch secret the member knew, for the access-control demo.
        state.removedSnapshot = { leaf: member, epoch: state.epoch, encryptionSecret: state.epochSecrets.encryption.slice() };
        await commitWithProposals(state, [{ type: 'remove', leafIndex: member }], committer);
        state.narration = buildRemoveNarration(state, member, committer, prevEpoch);
        rerender();
      }),
      onAdd: () => guard(async () => {
        const before = new Set(state.activeMembers());
        const prevEpoch = state.epoch;
        await commitWithProposals(state, [{ type: 'add' }], 0);
        const added = state.activeMembers().find((l) => !before.has(l));
        state.narration = buildAddNarration(state, added, prevEpoch);
        rerender();
      }),
      onSend: (member: number, text: string) => guard(async () => {
        await state.sendApplication(member, text);
        const gen = state.ratchets.get(member)?.appGeneration ?? 1;
        state.narration = buildSendNarration(state, member, gen);
        rerender();
      })
    })
  );

  main.appendChild(renderStatusBanner(state, animate, rerender, guard));
  if (state.tour.active) {
    main.appendChild(renderTour(state, rerender, guard));
  }
  main.appendChild(renderNarration(state));
  main.appendChild(tree);
  main.appendChild(controls);
  main.appendChild(transcript);
  main.appendChild(renderKeySchedule(state));
  main.appendChild(renderConvergencePanel(state, rerender, guard));
  main.appendChild(renderFsPanel(state, rerender, guard));
  main.appendChild(renderPcsPanel(state, rerender, guard));
  main.appendChild(renderAccessPanel(state, rerender, guard));
  main.appendChild(renderScenarioPanel(state, rerender, guard));
  main.appendChild(renderExplainer());
  main.appendChild(renderComparisonPanel());

  // Scrollable output regions (overflow:auto) must be keyboard-focusable and
  // named so keyboard users can reach their content (WCAG 2.1.1 /
  // scrollable-region-focusable). <pre> code dumps and horizontally scrolling
  // tables both qualify.
  for (const el of Array.from(main.querySelectorAll<HTMLElement>('pre'))) {
    if (!el.hasAttribute('tabindex')) el.setAttribute('tabindex', '0');
    if (!el.hasAttribute('role')) el.setAttribute('role', 'region');
    if (!el.hasAttribute('aria-label')) el.setAttribute('aria-label', 'Code output');
  }
  for (const el of Array.from(main.querySelectorAll<HTMLElement>('.table-scroll'))) {
    if (!el.hasAttribute('tabindex')) el.setAttribute('tabindex', '0');
    if (!el.hasAttribute('role')) el.setAttribute('role', 'region');
    if (!el.hasAttribute('aria-label')) el.setAttribute('aria-label', 'Scrollable table');
  }

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
