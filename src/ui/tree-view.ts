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

export function renderTreePanel(state: GroupStateModel, animate = false): HTMLDivElement {
  const wrapper = document.createElement('div');
  const tree = state.tree;
  const leaves = tree.leaves;
  const n = leaves.length;

  const svg = svgEl('svg');
  svg.setAttribute('viewBox', `0 0 ${SVG_W} ${SVG_H}`);
  svg.setAttribute('role', 'img');
  svg.setAttribute('aria-label', `MLS TreeKEM ratchet tree — ${n} member${n !== 1 ? 's' : ''}`);
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
  // Leaves: evenly distributed along x; parent x = midpoint of children;
  // y = linearly mapped from level (0 = leaf→bottom, maxLevel = root→top).
  const maxLevel = Math.max(...[...allNodes].map((idx) => tree.level(idx)));
  const positions = new Map<number, { x: number; y: number }>();

  // Leaf x spacing
  const spacing = n > 1 ? (SVG_W - SVG_PAD * 2) / (n - 1) : 0;
  for (let i = 0; i < n; i++) {
    const lv = tree.level(leaves[i]) === 0 ? 0 : tree.level(leaves[i]);
    const y = maxLevel === 0 ? LEAF_Y : LEAF_Y - (lv / maxLevel) * (LEAF_Y - ROOT_Y);
    positions.set(leaves[i], { x: SVG_PAD + spacing * i, y });
  }

  // Internal nodes — process bottom-up by level
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

  // ── 3. Compute highlight sets ────────────────────────────────────────────
  const committer = state.lastCommitterLeaf;
  const directPathSet = new Set<number>();
  const copathSet = new Set<number>();

  if (committer !== null && leaves.includes(committer)) {
    for (const p of tree.directPath(committer)) directPathSet.add(p);
    for (const c of tree.copath(committer)) copathSet.add(c);
  }

  // ── 4. Draw edges (lines) before circles so circles sit on top ──────────
  const edgeGroup = svgEl('g');
  edgeGroup.setAttribute('aria-hidden', 'true');

  for (const idx of allNodes) {
    if (tree.level(idx) === 0) continue; // leaf, no children to draw
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

      const onPath = directPathSet.has(idx) || directPathSet.has(child) ||
                     copathSet.has(idx) || copathSet.has(child);
      line.setAttribute('stroke', onPath ? 'var(--accent)' : 'var(--border)');
      line.setAttribute('stroke-width', onPath ? '2' : '1');
      // Animate the committer's direct-path edges filling in bottom-to-top.
      if (animate && directPathSet.has(idx)) {
        line.classList.add('tree-anim');
        line.style.animationDelay = `${tree.level(idx) * 0.13}s`;
      }
      edgeGroup.appendChild(line);
    }
  }
  svg.appendChild(edgeGroup);

  // ── 5. Draw nodes ────────────────────────────────────────────────────────
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

    const circle = svgEl('circle');
    circle.setAttribute('cx', `${pos.x}`);
    circle.setAttribute('cy', `${pos.y}`);
    circle.setAttribute('r', isLeaf ? '9' : '7');
    circle.setAttribute('fill', fill);
    circle.setAttribute('stroke', stroke);
    circle.setAttribute('stroke-width', directPathSet.has(idx) || copathSet.has(idx) ? '2' : '1.5');
    circle.setAttribute('stroke-dasharray', strokeDash);
    // Pop the re-keyed direct-path nodes (and the committer) in, climbing up.
    if (animate && (directPathSet.has(idx) || idx === committer)) {
      circle.classList.add('tree-anim-node');
      circle.style.animationDelay = `${tree.level(idx) * 0.13}s`;
    }
    circle.setAttribute('role', 'img');
    const who = isLeaf && !node?.blank ? ` (${memberName(idx)})` : '';
    circle.setAttribute('aria-label',
      `${isLeaf ? 'Leaf' : 'Parent'} node ${idx}${who} — ${node?.blank ? 'blank' : 'active'}${directPathSet.has(idx) ? ', direct path' : ''}${copathSet.has(idx) ? ', copath' : ''}`
    );
    svg.appendChild(circle);

    // Index label (small, beside the node)
    const text = svgEl('text');
    text.setAttribute('x', `${pos.x + 11}`);
    text.setAttribute('y', `${pos.y + 4}`);
    text.setAttribute('font-size', '10');
    text.setAttribute('fill', 'var(--muted)');
    text.setAttribute('aria-hidden', 'true');
    text.textContent = `${idx}`;
    svg.appendChild(text);

    // Member name beneath each active leaf — anchors the abstract tree to people
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

  wrapper.appendChild(svg);

  // ── 6. Legend + caption as accessible HTML below the diagram ──────────────
  // Base entries explain node colours/shapes; the path entries only appear once
  // a commit has set a committer, since they describe that specific commit.
  const legendItems: Array<{ swatch: string; label: string }> = [
    { swatch: 'leaf', label: 'member leaf' },
    { swatch: 'parent', label: 'parent — intermediate keypair' },
    { swatch: 'blank', label: 'blank — no key here' }
  ];
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
    ? `${memberName(committer)} committed: the highlighted direct path got fresh keys, each encrypted only to the copath subtrees — that's the O(log n) update.`
    : 'Each member is a leaf; parent nodes hold shared keys derivable only by the members below them. Commit an Update to watch a direct path light up.';
  wrapper.appendChild(caption);

  return wrapper;
}
