import { GroupStateModel } from '../group/group-state';
import { memberName } from '../group/members';

const LEAF_Y = 210;
const ROOT_Y = 20;
const SVG_W = 860;
const SVG_H = 280;
const SVG_PAD = 40;

function svgEl<K extends keyof SVGElementTagNameMap>(tag: K): SVGElementTagNameMap[K] {
  return document.createElementNS('http://www.w3.org/2000/svg', tag);
}

const hex = (b: Uint8Array | undefined, n = 8): string =>
  b ? Array.from(b.slice(0, n)).map((x) => x.toString(16).padStart(2, '0')).join('') : '—';

// Leaves that sit UNDER a given node (i.e. members whose direct path passes
// through it). Those are exactly the members who can derive that node's secret.
function membersUnder(state: GroupStateModel, nodeIndex: number): number[] {
  const tree = state.tree;
  if (tree.level(nodeIndex) === 0) {
    return tree.nodes.get(nodeIndex)?.blank ? [] : [nodeIndex];
  }
  return tree.leaves.filter((leaf) => {
    if (tree.nodes.get(leaf)?.blank) return false;
    return leaf === nodeIndex || tree.directPath(leaf).includes(nodeIndex);
  });
}

export interface TreeViewCallbacks {
  onSelect: (nodeIndex: number | null) => void;
}

export function renderTreePanel(
  state: GroupStateModel,
  animate = false,
  callbacks?: TreeViewCallbacks
): HTMLDivElement {
  const wrapper = document.createElement('div');
  const tree = state.tree;
  const leaves = tree.leaves;
  const n = leaves.length;

  const svg = svgEl('svg');
  svg.setAttribute('viewBox', `0 0 ${SVG_W} ${SVG_H}`);
  // A group (not img) so the clickable node buttons inside are valid descendants
  // — an img role would make them nested-interactive (axe serious).
  svg.setAttribute('role', 'group');
  svg.setAttribute('aria-label', `MLS TreeKEM ratchet tree — ${n} member${n !== 1 ? 's' : ''}. Each node is a button; activate to inspect.`);
  svg.classList.add('tree-svg');

  if (n === 0) {
    wrapper.appendChild(svg);
    return wrapper;
  }

  // ── 1. Collect every node that exists in this tree ─────────────────────
  const allNodes = new Set<number>();
  for (const leaf of leaves) {
    allNodes.add(leaf);
    for (const p of tree.directPath(leaf)) allNodes.add(p);
  }

  // ── 2. Compute positions ────────────────────────────────────────────────
  const maxLevel = Math.max(...[...allNodes].map((idx) => tree.level(idx)));
  const positions = new Map<number, { x: number; y: number }>();

  const spacing = n > 1 ? (SVG_W - SVG_PAD * 2) / (n - 1) : 0;
  for (let i = 0; i < n; i++) {
    const lv = tree.level(leaves[i]) === 0 ? 0 : tree.level(leaves[i]);
    const y = maxLevel === 0 ? LEAF_Y : LEAF_Y - (lv / maxLevel) * (LEAF_Y - ROOT_Y);
    positions.set(leaves[i], { x: SVG_PAD + spacing * i, y });
  }

  const internals = [...allNodes]
    .filter((idx) => tree.level(idx) > 0)
    .sort((a, b) => tree.level(a) - tree.level(b));

  for (const idx of internals) {
    const lv = tree.level(idx);
    const y = maxLevel === 0 ? ROOT_Y : LEAF_Y - (lv / maxLevel) * (LEAF_Y - ROOT_Y);
    const l = tree.left(idx);
    const r = tree.right(idx);
    const lx = l !== null && positions.has(l) ? positions.get(l)!.x : null;
    const rx = r !== null && positions.has(r) ? positions.get(r)!.x : null;
    const x = lx !== null && rx !== null
      ? (lx + rx) / 2
      : lx ?? rx ?? SVG_W / 2;
    positions.set(idx, { x, y });
  }

  // ── 3. Commit highlight sets (from the last committer) ───────────────────
  const committer = state.lastCommitterLeaf;
  const directPathSet = new Set<number>();
  const copathSet = new Set<number>();

  if (committer !== null && leaves.includes(committer)) {
    for (const p of tree.directPath(committer)) directPathSet.add(p);
    for (const c of tree.copath(committer)) copathSet.add(c);
  }

  // ── 3b. Selection highlight (from a clicked node) ────────────────────────
  // Selecting a LEAF shows that member's own direct path (what they can derive)
  // and marks every other node as "blind to them". Selecting a PARENT marks the
  // members that can derive it. This is the who-knows-what intuition.
  const selected = state.selectedNode;
  const selectedIsLeaf = selected !== null && tree.level(selected) === 0;
  const selDirectPath = new Set<number>();
  const selBlind = new Set<number>();
  const selDerivers = new Set<number>();

  if (selected !== null && allNodes.has(selected)) {
    if (selectedIsLeaf) {
      selDirectPath.add(selected);
      for (const p of tree.directPath(selected)) selDirectPath.add(p);
      for (const idx of allNodes) if (!selDirectPath.has(idx)) selBlind.add(idx);
    } else {
      for (const m of membersUnder(state, selected)) selDerivers.add(m);
    }
  }

  // ── 4. Draw edges ────────────────────────────────────────────────────────
  const edgeGroup = svgEl('g');
  edgeGroup.setAttribute('aria-hidden', 'true');

  for (const idx of allNodes) {
    if (tree.level(idx) === 0) continue;
    const pos = positions.get(idx);
    if (!pos) continue;
    for (const child of [tree.left(idx), tree.right(idx)]) {
      if (child === null) continue;
      const cpos = positions.get(child);
      if (!cpos) continue;
      const line = svgEl('line');
      line.setAttribute('x1', `${pos.x}`);
      line.setAttribute('y1', `${pos.y}`);
      line.setAttribute('x2', `${cpos.x}`);
      line.setAttribute('y2', `${cpos.y}`);

      const onSelPath = selDirectPath.has(idx) && selDirectPath.has(child);
      const onPath = directPathSet.has(idx) || directPathSet.has(child) ||
                     copathSet.has(idx) || copathSet.has(child);
      line.setAttribute('stroke', onSelPath ? 'var(--focus-ring)' : (onPath ? 'var(--accent)' : 'var(--border)'));
      line.setAttribute('stroke-width', onSelPath || onPath ? '2' : '1');
      if (animate && directPathSet.has(idx)) {
        line.classList.add('tree-anim');
        line.style.animationDelay = `${tree.level(idx) * 0.13}s`;
      }
      edgeGroup.appendChild(line);
    }
  }
  svg.appendChild(edgeGroup);

  // ── 5. Draw nodes (interactive) ──────────────────────────────────────────
  for (const idx of allNodes) {
    const pos = positions.get(idx);
    if (!pos) continue;

    const node = tree.nodes.get(idx);
    const isLeaf = tree.level(idx) === 0;

    let fill: string;
    let stroke: string;
    let strokeDash = '0';

    if (node?.blank) {
      fill = 'none';
      stroke = 'var(--border)';
      strokeDash = '3 2';
    } else if (selected !== null && selBlind.has(idx)) {
      // Dim the subtrees the selected member is blind to.
      fill = 'var(--border)';
      stroke = 'var(--border)';
    } else if (selDirectPath.has(idx) || selDerivers.has(idx) || idx === selected) {
      fill = 'var(--focus-ring)';
      stroke = 'var(--focus-ring)';
    } else if (directPathSet.has(idx)) {
      fill = 'var(--accent)';
      stroke = 'var(--accent)';
    } else if (copathSet.has(idx)) {
      fill = 'var(--danger)';
      stroke = 'var(--danger)';
    } else if (committer !== null && idx === committer) {
      fill = 'var(--accent)';
      stroke = 'var(--focus-ring)';
    } else {
      fill = isLeaf ? 'var(--accent)' : 'var(--text)';
      stroke = 'var(--border)';
    }

    // A generous transparent hit target makes small nodes easy to click/tap.
    const hit = svgEl('circle');
    hit.setAttribute('cx', `${pos.x}`);
    hit.setAttribute('cy', `${pos.y}`);
    hit.setAttribute('r', '16');
    hit.setAttribute('fill', 'transparent');

    const circle = svgEl('circle');
    circle.setAttribute('cx', `${pos.x}`);
    circle.setAttribute('cy', `${pos.y}`);
    circle.setAttribute('r', isLeaf ? '9' : '7');
    circle.setAttribute('fill', fill);
    circle.setAttribute('stroke', stroke);
    circle.setAttribute('stroke-width', selDirectPath.has(idx) || selDerivers.has(idx) || idx === selected || directPathSet.has(idx) || copathSet.has(idx) ? '2' : '1.5');
    circle.setAttribute('stroke-dasharray', strokeDash);
    if (animate && (directPathSet.has(idx) || idx === committer)) {
      circle.classList.add('tree-anim-node');
      circle.style.animationDelay = `${tree.level(idx) * 0.13}s`;
    }

    // Make each node a real, keyboard-operable button so the tree is explorable
    // by mouse, touch, and keyboard alike.
    const g = svgEl('g');
    g.setAttribute('role', 'button');
    g.setAttribute('tabindex', '0');
    g.id = `tree-node-${idx}`;
    g.classList.add('tree-node-hit');
    const who = isLeaf && !node?.blank ? ` (${memberName(idx)})` : '';
    const derivers = !isLeaf && !node?.blank ? membersUnder(state, idx).map(memberName) : [];
    const deriveLabel = derivers.length ? `, derivable by ${derivers.join(', ')}` : '';
    const isSel = idx === selected;
    g.setAttribute('aria-label',
      `${isLeaf ? 'Leaf' : 'Parent'} node ${idx}${who} — ${node?.blank ? 'blank, no key' : 'active'}${deriveLabel}${directPathSet.has(idx) ? ', on the last commit’s direct path' : ''}${copathSet.has(idx) ? ', on the copath' : ''}. ${isSel ? 'Selected. Activate to clear.' : 'Activate to inspect.'}`
    );
    const toggle = () => callbacks?.onSelect(isSel ? null : idx);
    g.addEventListener('click', toggle);
    g.addEventListener('keydown', (ev: KeyboardEvent) => {
      if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); toggle(); }
    });
    g.appendChild(hit);
    g.appendChild(circle);

    // Selection ring
    if (isSel) {
      const ring = svgEl('circle');
      ring.setAttribute('cx', `${pos.x}`);
      ring.setAttribute('cy', `${pos.y}`);
      ring.setAttribute('r', isLeaf ? '14' : '12');
      ring.setAttribute('fill', 'none');
      ring.setAttribute('stroke', 'var(--focus-ring)');
      ring.setAttribute('stroke-width', '2');
      ring.setAttribute('stroke-dasharray', '3 2');
      g.appendChild(ring);
    }
    svg.appendChild(g);

    // Index label
    const text = svgEl('text');
    text.setAttribute('x', `${pos.x + 11}`);
    text.setAttribute('y', `${pos.y + 4}`);
    text.setAttribute('font-size', '10');
    text.setAttribute('fill', 'var(--muted)');
    text.setAttribute('aria-hidden', 'true');
    text.textContent = `${idx}`;
    svg.appendChild(text);

    if (isLeaf && !node?.blank) {
      const nameText = svgEl('text');
      nameText.setAttribute('x', `${pos.x}`);
      nameText.setAttribute('y', `${pos.y + 25}`);
      nameText.setAttribute('font-size', '13');
      nameText.setAttribute('font-weight', '600');
      nameText.setAttribute('text-anchor', 'middle');
      nameText.setAttribute('fill', 'var(--text)');
      nameText.setAttribute('aria-hidden', 'true');
      nameText.textContent = memberName(idx);
      svg.appendChild(nameText);
    }
  }

  // ── 5b. Sealed-packet animation: on a commit, a small packet flies from each
  // committed direct-path node to each copath leaf it was HPKE-sealed to. This
  // makes "encrypted only to its copath" literally visible.
  if (animate && committer !== null && directPathSet.size > 0) {
    const packets = svgEl('g');
    packets.setAttribute('aria-hidden', 'true');
    // Each direct-path node's fresh secret is HPKE-sealed to the resolution of
    // the matching copath node. updatePathTargets pairs them up exactly as the
    // real UpdatePath does, so the packets trace the true encrypt-to-copath step.
    for (const target of tree.updatePathTargets(committer)) {
      const from = positions.get(target.nodeIndex);
      if (!from) continue;
      for (const leaf of target.resolution) {
        const to = positions.get(leaf);
        if (!to) continue;
        const packet = svgEl('rect');
        packet.setAttribute('width', '9');
        packet.setAttribute('height', '7');
        packet.setAttribute('rx', '1.5');
        packet.setAttribute('x', `${from.x - 4.5}`);
        packet.setAttribute('y', `${from.y - 3.5}`);
        packet.setAttribute('fill', 'var(--focus-ring)');
        packet.setAttribute('stroke', 'var(--bg)');
        packet.setAttribute('stroke-width', '0.5');
        packet.classList.add('tree-packet');
        const anim = svgEl('animateMotion');
        anim.setAttribute('dur', '0.7s');
        anim.setAttribute('begin', `${tree.level(target.nodeIndex) * 0.13}s`);
        anim.setAttribute('fill', 'freeze');
        anim.setAttribute('path', `M0,0 L${to.x - from.x},${to.y - from.y}`);
        packet.appendChild(anim);
        packets.appendChild(packet);
      }
    }
    svg.appendChild(packets);
  }

  wrapper.appendChild(svg);

  // ── 6. Selection readout (accessible HTML, live region) ──────────────────
  const readout = document.createElement('div');
  readout.className = 'tree-readout';
  readout.setAttribute('aria-live', 'polite');
  if (selected !== null && allNodes.has(selected)) {
    const node = tree.nodes.get(selected);
    const title = document.createElement('p');
    title.className = 'tree-readout-title';
    if (selectedIsLeaf) {
      const path = tree.directPath(selected);
      title.textContent = node?.blank
        ? `Leaf ${selected} — blank (no member here)`
        : `${memberName(selected)} · leaf ${selected}`;
      readout.appendChild(title);
      if (!node?.blank) {
        const p = document.createElement('p');
        p.className = 'muted';
        p.textContent = path.length
          ? `Can derive its own leaf key and every node on its direct path: node${path.length === 1 ? '' : 's'} ${path.join(', ')} (highlighted). Everything else in the tree is dimmed — ${memberName(selected)} is blind to it.`
          : `The only member — it is the whole tree.`;
        readout.appendChild(p);
        const k = document.createElement('p');
        k.className = 'muted tree-readout-key';
        k.textContent = `HPKE public key: ${hex(node?.leafNode?.hpkePublicKey)}…`;
        readout.appendChild(k);
      }
    } else {
      title.textContent = node?.blank ? `Parent node ${selected} — blank (no key here)` : `Parent node ${selected}`;
      readout.appendChild(title);
      const derivers = membersUnder(state, selected).map(memberName);
      const p = document.createElement('p');
      p.className = 'muted';
      p.textContent = node?.blank
        ? `Blanked: no shared key lives here right now. A future commit re-keys it.`
        : `Derivable by: ${derivers.join(', ') || '—'} (the members whose direct path runs through it, highlighted). No one outside this subtree can compute it.`;
      readout.appendChild(p);
      if (!node?.blank) {
        const k = document.createElement('p');
        k.className = 'muted tree-readout-key';
        k.textContent = `HPKE public key: ${hex(node?.parentNode?.encryptionKey)}…`;
        readout.appendChild(k);
      }
    }
    const clear = document.createElement('button');
    clear.className = 'tree-readout-clear';
    clear.textContent = 'Clear selection';
    clear.setAttribute('aria-label', 'Clear the selected tree node');
    clear.onclick = () => callbacks?.onSelect(null);
    readout.appendChild(clear);
  } else {
    const p = document.createElement('p');
    p.className = 'muted';
    p.textContent = 'Click any node to inspect it: a member leaf shows exactly which keys that person can derive; a parent node shows who shares it and its HPKE public key.';
    readout.appendChild(p);
  }
  wrapper.appendChild(readout);

  // ── 7. Legend + caption ──────────────────────────────────────────────────
  const legendItems: Array<{ swatch: string; label: string }> = [
    { swatch: 'leaf', label: 'member leaf' },
    { swatch: 'parent', label: 'parent — intermediate keypair' },
    { swatch: 'blank', label: 'blank — no key here' }
  ];
  if (selected !== null) {
    legendItems.push({ swatch: 'sel', label: selectedIsLeaf ? 'selected member can derive these' : 'members who can derive the selected node' });
  }
  if (committer !== null && directPathSet.size > 0) {
    legendItems.push({ swatch: 'path', label: `direct path — ${memberName(committer)} re-keyed these` });
    legendItems.push({ swatch: 'copath', label: 'copath — subtrees the new keys are sent to' });
  }

  const legend = document.createElement('ul');
  legend.className = 'tree-legend';
  legend.setAttribute('aria-label', 'Tree node legend');
  for (const { swatch, label } of legendItems) {
    const li = document.createElement('li');
    const dot = document.createElement('span');
    dot.className = `swatch swatch-${swatch}`;
    dot.setAttribute('aria-hidden', 'true');
    li.appendChild(dot);
    li.appendChild(document.createTextNode(label));
    legend.appendChild(li);
  }
  wrapper.appendChild(legend);

  const caption = document.createElement('p');
  caption.className = 'muted tree-caption';
  caption.textContent = committer !== null && directPathSet.size > 0
    ? `${memberName(committer)} committed: the highlighted direct path got fresh keys, each sealed (watch the packets fly) only to the copath subtrees — that's the O(log n) update.`
    : 'Each member is a leaf; parent nodes hold shared keys derivable only by the members below them. Click a node to explore, or commit an Update to watch a direct path light up.';
  wrapper.appendChild(caption);

  return wrapper;
}
