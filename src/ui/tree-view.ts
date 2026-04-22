import { GroupStateModel } from '../group/group-state';

function nodeY(level: number, maxLevel: number): number {
  return 20 + ((maxLevel - level) / Math.max(1, maxLevel)) * 200;
}

export function renderTreePanel(state: GroupStateModel): SVGSVGElement {
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('viewBox', '0 0 860 260');
  svg.setAttribute('role', 'img');
  svg.setAttribute('aria-label', `MLS TreeKEM structure with ${state.tree.leaves.length} members`);
  svg.classList.add('tree-svg');

  const leaves = state.tree.leaves;
  const spacing = 780 / Math.max(1, leaves.length - 1);

  const positions = new Map<number, { x: number; y: number }>();
  for (let i = 0; i < leaves.length; i += 1) {
    positions.set(leaves[i], { x: 40 + spacing * i, y: 230 });
  }

  for (const leaf of leaves) {
    const path = state.tree.directPath(leaf);
    for (let i = 0; i < path.length; i += 1) {
      const node = path[i];
      const x = positions.get(leaf)?.x ?? 40;
      positions.set(node, { x, y: nodeY(i + 1, path.length) });
    }
  }

  for (const [idx, pos] of positions.entries()) {
    const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    circle.setAttribute('cx', `${pos.x}`);
    circle.setAttribute('cy', `${pos.y}`);
    circle.setAttribute('r', '9');

    const node = state.tree.nodes.get(idx);
    const isLeaf = idx % 2 === 0;
    const fill = node?.blank ? 'none' : isLeaf ? 'var(--accent)' : 'var(--text)';
    circle.setAttribute('fill', fill);
    circle.setAttribute('stroke', 'var(--border)');
    circle.setAttribute('stroke-dasharray', node?.blank ? '3 2' : '0');
    
    const nodeType = isLeaf ? 'Leaf' : 'Parent';
    const nodeStatus = node?.blank ? 'blank' : 'active';
    circle.setAttribute('aria-label', `${nodeType} node ${idx} (${nodeStatus})`);
    circle.setAttribute('role', 'img');
    
    svg.appendChild(circle);

    const text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    text.setAttribute('x', `${pos.x + 10}`);
    text.setAttribute('y', `${pos.y + 3}`);
    text.setAttribute('font-size', '10');
    text.setAttribute('fill', 'var(--muted)');
    text.setAttribute('aria-hidden', 'true');
    text.textContent = `${idx}`;
    svg.appendChild(text);
  }

  return svg;
}
