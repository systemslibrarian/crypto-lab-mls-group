// Human-readable identities for group members.
//
// MLS itself only knows leaf indices; names exist purely to make the demo
// legible. The mapping is stable: a leaf keeps its name across epochs, and a
// blank leaf that is later refilled by an Add reuses the same name. Leaves live
// at even node indices (0, 2, 4, …), so leafIndex / 2 is a stable name slot.
const NAMES = [
  'Alice', 'Bob', 'Charlie', 'Dave', 'Eve', 'Frank', 'Grace', 'Heidi',
  'Ivan', 'Judy', 'Mallory', 'Niaj', 'Olivia', 'Peggy', 'Sybil', 'Trent',
  'Victor', 'Walter', 'Yara', 'Zane'
];

export function memberName(leafIndex: number): string {
  const slot = Math.floor(leafIndex / 2);
  return NAMES[slot] ?? `Member ${slot + 1}`;
}

// "Alice · leaf 0" — name first (what learners track), leaf index second
// (what the protocol tracks).
export function memberLabel(leafIndex: number): string {
  return `${memberName(leafIndex)} · leaf ${leafIndex}`;
}
