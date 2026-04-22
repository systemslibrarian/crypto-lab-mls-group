import { GroupStateModel } from '../group/group-state';

const LEAF_Y = 220;
const ROOT_Y = 20;
const SVG_W = 860;
const SVG_PAD = 40;

function svgEl<K extends keyof SVGElementTagNameMap>(tag: K): SVGElementTagNameMap[K] {
  return document.createElementNS('http://www.w3.org/2000/svg', tag);
}

export function renderTreePanel(state: GroupStateModel): SVGSVGElement {
  const tree = state.tree;
  const leaves = tree.leaves;
  const n = leaves.length;

  const svg = svgEl('svg');
  svg.setAttribute('viewBox', `0 0 ${SVG_W} 260`);
  svg.setAttribute('role', 'img');
  svg.setAttribute('aria-label', `MLS TreeKEM ratchet tree — ${n} member${n !== 1 ? 's' : ''}`);
  svg.classList.add('tree-svg');

  if (n === 0) return svg;

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
    circle.setAttribute('role', 'img');
    circle.setAttribute('aria-label',
      `${isLeaf ? 'Leaf' : 'Parent'} node ${idx} — ${node?.blank ? 'blank' : 'active'}${directPathSet.has(idx) ? ', direct path' : ''}${copathSet.has(idx) ? ', copath' : ''}`
    );
    svg.appendChild(circle);

    // Index label
    const text = svgEl('text');
    text.setAttribute('x', `${pos.x + 11}`);
    text.setAttribute('y', `${pos.y + 4}`);
    text.setAttribute('font-size', '10');
    text.setAttribute('fill', 'var(--muted)');
    text.setAttribute('aria-hidden', 'true');
    text.textContent = `${idx}`;
    svg.appendChild(text);
  }

  // ── 6. Legend (only when committer is known) ─────────────────────────────
  if (committer !== null && directPathSet.size > 0) {
    const legend = svgEl('g');
    legend.setAttribute('aria-hidden', 'true');
    const items: Array<[string, string]> = [
      ['var(--accent)', `direct path (leaf ${committer})`],
      ['var(--danger)', 'copath targets']
    ];
    items.forEach(([color, label], i) => {
      const dot = svgEl('circle');
      dot.setAttribute('cx', `${SVG_W - 170}`);
      dot.setAttribute('cy', `${10 + i * 16}`);
      dot.setAttribute('r', '5');
      dot.setAttribute('fill', color);
      legend.appendChild(dot);
      const t = svgEl('text');
      t.setAttribute('x', `${SVG_W - 160}`);
      t.setAttribute('y', `${14 + i * 16}`);
      t.setAttribute('font-size', '10');
      t.setAttribute('fill', 'var(--muted)');
      t.textContent = label;
      legend.appendChild(t);
    });
    svg.appendChild(legend);
  }

  return svg;
}
