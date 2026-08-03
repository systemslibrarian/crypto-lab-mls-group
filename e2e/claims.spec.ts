import { expect, test as base, type Locator, type Page } from '@playwright/test';

/**
 * Functional gate on the claims this lab makes on screen.
 *
 * The a11y and border-contrast suites prove the page is reachable and legible;
 * the Vitest suites prove the TreeKEM/key-schedule math. Neither proves the
 * *page* reaches the states it advertises. This suite drives the real controls
 * and checks each headline against the page's own numbers: the narration's
 * "epoch A → B" against the banner, the convergence proof against the Key
 * Schedule panel's commit_secret chip, and every security claim (forward
 * secrecy, PCS healing, removed-member lockout) against the two values the
 * panel printed to justify it.
 */

const test = base.extend<{ pageErrors: string[] }>({
  pageErrors: [
    async ({ page }, use) => {
      const errors: string[] = [];
      page.on('pageerror', (error) => errors.push(`pageerror: ${error.message}`));
      page.on('console', (message) => {
        if (message.type() === 'error') errors.push(`console.error: ${message.text()}`);
      });
      await use(errors);
      expect(errors, 'uncaught page errors').toEqual([]);
    },
    { auto: true },
  ],
});

const GATED_PANELS = [
  'Key Schedule',
  'TreeKEM Convergence',
  'Forward Secrecy Walkthrough',
  'PCS Recovery Walkthrough',
  'Access Control: Removed Member',
  'Scenario Presets',
  'Concepts',
  'Comparison Panel',
];

async function open(page: Page): Promise<void> {
  await page.goto('.');
  await expect(page.locator('.status-banner')).toContainText('Epoch');
}

/** A revealed panel by its exact heading. */
function panel(page: Page, title: string): Locator {
  return page
    .locator('section.panel:not(.panel-locked)')
    .filter({ has: page.locator(`h2:text-is("${title}")`) });
}

async function flat(locator: Locator): Promise<string> {
  return (await locator.innerText()).replace(/\s+/g, ' ').trim();
}

function grab(source: string, pattern: RegExp): RegExpMatchArray {
  const match = source.match(pattern);
  expect(match, `expected ${pattern} in: ${source}`).not.toBeNull();
  return match as RegExpMatchArray;
}

/** The banner's epoch value, as its own element (so waits can target it). */
const epochStat = (page: Page): Locator =>
  page.locator('.status-banner .stat').nth(0).locator('.stat-value');
/** The banner's "Members (n)" label and its comma-separated names. */
const membersLabel = (page: Page): Locator =>
  page.locator('.status-banner .stat').nth(1).locator('.stat-label');
const membersStat = (page: Page): Locator =>
  page.locator('.status-banner .stat').nth(1).locator('.stat-value');

/** Epoch and membership as the status banner currently reports them. */
async function banner(page: Page): Promise<{ epoch: number; count: number; members: string[] }> {
  const epoch = Number((await epochStat(page).innerText()).trim());
  const count = Number(grab(await membersLabel(page).innerText(), /\((\d+)\)/)[1]);
  const names = (await membersStat(page).innerText()).trim();
  return { epoch, count, members: names === '\u2014' ? [] : names.split(', ') };
}

/** Reveal every gated panel at once. */
async function revealAll(page: Page): Promise<void> {
  await page.getByRole('button', { name: 'Reveal all advanced panels at once' }).click();
  await expect(page.locator('section.panel-locked')).toHaveCount(0);
}

// ---------------------------------------------------------------------------

test('progressive disclosure: the internals stay gated until revealed', async ({ page }) => {
  await open(page);

  const start = await banner(page);
  expect(start.epoch).toBe(0);
  expect(start.members).toEqual(['Alice', 'Bob', 'Charlie']);
  expect(start.count).toBe(start.members.length);

  // Every proof/internals panel starts as a teaser with a reveal button.
  await expect(page.locator('section.panel-locked')).toHaveCount(GATED_PANELS.length);
  for (const title of GATED_PANELS) {
    await expect(
      page.locator('section.panel-locked').filter({ has: page.locator(`h2:text-is("${title}")`) }),
    ).toHaveCount(1);
    await expect(panel(page, title)).toHaveCount(0);
  }

  await revealAll(page);
  for (const title of GATED_PANELS) {
    await expect(panel(page, title)).toHaveCount(1);
  }
  // Once everything is revealed the "show all" affordance retires itself.
  await expect(page.locator('.reveal-all')).toHaveCount(0);
});

test('lifecycle: add, update and remove each advance the epoch the narration claims', async ({
  page,
}) => {
  await open(page);

  // --- Add -----------------------------------------------------------------
  let before = await banner(page);
  await page.getByRole('button', { name: 'Add a new member to the group' }).click();
  await expect(membersLabel(page)).toHaveText(`Members (${before.count + 1})`);

  let after = await banner(page);
  expect(after.epoch).toBe(before.epoch + 1);
  expect(after.members).toEqual([...before.members, 'Dave']);

  let narration = await flat(page.locator('.narration'));
  expect(narration).toContain('Dave joined the group');
  // The narration's epoch transition must be the one the banner shows.
  expect(narration).toContain(`the epoch advanced ${before.epoch} → ${after.epoch}`);
  expect(grab(narration, /A leaf was allocated \(leaf (\d+)\)/)[1]).toBe('6');

  // --- Update --------------------------------------------------------------
  before = after;
  await page.getByRole('button', { name: /rotates their keys.*leaf 0/ }).click();
  await expect(epochStat(page)).toHaveText(String(before.epoch + 1));
  after = await banner(page);
  expect(after.members, 'an update changes keys, not membership').toEqual(before.members);

  narration = await flat(page.locator('.narration'));
  expect(narration).toContain('Alice rotated their keys (Update)');
  expect(narration).toContain(`Epoch ${before.epoch} → ${after.epoch}`);
  // The path it says it re-keyed is a real, non-empty direct path.
  const path = grab(narration, /up their direct path: nodes? ([\d, ]+)\./)[1]!
    .split(', ')
    .map(Number);
  expect(path.length).toBeGreaterThan(0);

  // The transcript is the protocol log for the same events.
  const top = await flat(page.locator('.transcript-item').first());
  expect(top).toContain(`epoch ${after.epoch}`);
  expect(top).toMatch(/COMMIT/);

  // --- Remove --------------------------------------------------------------
  before = after;
  await page.getByRole('button', { name: /^Remove Bob \(leaf 2\) from the group$/ }).click();
  await expect(membersLabel(page)).toHaveText(`Members (${before.count - 1})`);
  after = await banner(page);
  expect(after.epoch).toBe(before.epoch + 1);
  expect(after.members).toEqual(before.members.filter((name) => name !== 'Bob'));

  narration = await flat(page.locator('.narration'));
  expect(narration).toContain('Bob was removed');
  expect(narration).toContain('Leaf 2 and every node on its direct path were blanked');
  expect(narration).toContain(`Epoch ${before.epoch} → ${after.epoch}`);

  // Bob's controls are gone with him; the survivors keep theirs.
  await expect(page.getByRole('button', { name: /^Remove Bob/ })).toHaveCount(0);
  for (const name of after.members) {
    await expect(page.getByRole('button', { name: new RegExp(`^Remove ${name} `) })).toHaveCount(1);
  }
});

test('convergence: every member derives one root secret, and it is this epoch commit_secret', async ({
  page,
}) => {
  await open(page);
  await revealAll(page);

  // Convergence is only tied to the live epoch after a real path commit.
  await page.getByRole('button', { name: /rotates their keys.*leaf 0/ }).click();
  await expect(epochStat(page)).toHaveText('1');

  await page
    .getByRole('button', { name: /Independently derive the root secret for every member/ })
    .click();

  const convergence = panel(page, 'TreeKEM Convergence');
  await expect(convergence).toContainText('independently derived the same root secret');

  const rows = convergence.locator('tbody tr');
  const state = await banner(page);
  await expect(rows).toHaveCount(state.count);

  const secrets = new Set<string>();
  for (let i = 0; i < state.count; i += 1) {
    const cells = await rows.nth(i).locator('th, td').allInnerTexts();
    const [member, via, secret, agrees] = cells.map((c) => c.trim());
    expect(state.members).toContain(member);
    // Exactly one member ratchets; everyone else decrypts.
    expect(via === 'ratchet up own path' || via === 'HPKE-decrypt + ratchet').toBe(true);
    secrets.add(grab(secret!, /^([0-9a-f]{16})…$/)[1]!);
    expect(agrees).toBe('✓ yes');
  }
  // Convergence means literally one value across all members.
  expect(secrets.size, 'all members must land on the same root secret').toBe(1);
  const shared = [...secrets][0]!;

  const verdict = await flat(convergence);
  expect(verdict).toContain(`All ${state.count} members independently derived the same root secret`);
  expect(verdict).toContain(shared);
  expect(verdict).toContain(`This is epoch ${state.epoch}'s commit_secret`);
  expect(verdict).toContain('✓ matches');
  expect(verdict).not.toContain('Secrets diverged');

  // Cross-panel: that shared secret IS the Key Schedule's commit_secret chip.
  const keySchedule = await flat(panel(page, 'Key Schedule'));
  expect(grab(keySchedule, /commit_secret ([0-9a-f]{16})…/i)[1]).toBe(shared);
});

test('forward secrecy: after the epoch advances the captured key cannot be re-derived', async ({
  page,
}) => {
  await open(page);
  await revealAll(page);

  const fs = panel(page, 'Forward Secrecy Walkthrough');
  await page.getByRole('button', { name: /Record the message key/ }).click();
  await expect(fs).toContainText('captured in epoch');

  const captured = grab(
    await flat(fs),
    /captured in epoch (\d+) \((\w+)\): encryption_secret: ([0-9a-f]{16})… message key: ([0-9a-f]{32})/,
  );
  const capturedEpoch = Number(captured[1]);
  const capturedKey = captured[4]!;
  expect(capturedEpoch).toBe((await banner(page)).epoch);

  await page.getByRole('button', { name: /commit an Update so the epoch advances/ }).click();
  await expect(fs).toContainText('same derivation, now in epoch');

  const now = await banner(page);
  expect(now.epoch).toBe(capturedEpoch + 1);

  const after = await flat(fs);
  const nowKey = grab(after, /same derivation, now in epoch (\d+): message key: ([0-9a-f]{32})/);
  expect(Number(nowKey[1])).toBe(now.epoch);
  // The claim: the same derivation now yields a different key.
  expect(nowKey[2]).not.toBe(capturedKey);
  expect(after).toContain(`✓ Different key — the epoch-${capturedEpoch} key cannot be reproduced`);
  expect(after, 'the panel must not silently pass when the keys match').not.toContain('keys match');
  // The captured key is still displayed for comparison, unchanged.
  expect(after).toContain(capturedKey);

  // Reset returns the walkthrough to step 1.
  await page.getByRole('button', { name: /Clear the captured key/ }).click();
  await expect(fs).not.toContainText('captured in epoch');
  await expect(page.getByRole('button', { name: /Record the message key/ })).toHaveCount(1);
});

test('post-compromise security: the exposed secret is still live until the Update, then is not', async ({
  page,
}) => {
  await open(page);
  await revealAll(page);

  const pcs = panel(page, 'PCS Recovery Walkthrough');
  await expect(pcs).toContainText('no compromise recorded');

  await page.getByRole('button', { name: /Expose .* pre-update epoch secret/ }).click();
  await expect(pcs).toContainText('EXPOSED TO ATTACKER');

  // Before the healing Update the attacker's secret IS the live one — the panel
  // must say so rather than claiming safety it has not earned yet.
  const exposed = await flat(pcs);
  const pre = grab(exposed, /pre-update epoch: ([0-9a-f]{16})\.\.\. ← EXPOSED TO ATTACKER/)[1]!;
  const liveBefore = grab(exposed, /current epoch: ([0-9a-f]{16})\.\.\./)[1]!;
  expect(liveBefore).toBe(pre);
  expect(exposed).toContain('⚠ Pre and post epoch secrets are equal — Update not yet applied');
  expect(exposed).toContain('Alice (leaf 0) — COMPROMISED');

  const before = await banner(page);
  await page.getByRole('button', { name: /commits an Update to advance the epoch/ }).click();
  await expect(epochStat(page)).toHaveText(String(before.epoch + 1));
  await expect(pcs).toContainText('Attacker locked out');

  const healed = await flat(pcs);
  expect(grab(healed, /pre-update epoch: ([0-9a-f]{16})\.\.\./)[1], 'the exposed secret is a record and must not move').toBe(pre);
  const liveAfter = grab(healed, /current epoch: ([0-9a-f]{16})\.\.\./)[1]!;
  expect(liveAfter).not.toBe(pre);
  expect(healed).toContain('✓ Pre-compromise secret ≠ current epoch — Attacker locked out ✓');
  expect(healed).not.toContain('Update not yet applied');

  // The transcript records the healing commit with both secrets.
  const log = await flat(page.locator('.transcript-item').first());
  expect(log).toContain('PCS recovery');
  expect(log).toContain('pre-update material cannot derive new epoch ✓');
  expect(log).not.toContain('unexpected');
});

test('access control: only a current member can open a message sent after the removal', async ({
  page,
}) => {
  await open(page);
  await revealAll(page);

  const access = panel(page, 'Access Control: Removed Member');
  // Failure path first: the demo refuses to run with nobody removed, and says why.
  await expect(access).toContainText('No one has been removed yet');
  await expect(
    page.getByRole('button', { name: /Encrypt a message in the current epoch/ }),
  ).toHaveCount(0);

  await page.getByRole('button', { name: /^Remove Bob \(leaf 2\) from the group$/ }).click();
  await expect(membersStat(page)).not.toContainText('Bob');
  const state = await banner(page);
  expect(state.members).not.toContain('Bob');

  await page.getByRole('button', { name: /Encrypt a message in the current epoch/ }).click();
  await expect(access).toContainText('[ciphertext]');

  const result = await flat(access);
  const sent = grab(result, /(\w+) \(epoch (\d+)\) sent: ([0-9a-f]{24})… \[ciphertext\]/);
  expect(Number(sent[2]), 'the message must be sent in the current epoch').toBe(state.epoch);
  expect(state.members).toContain(sent[1]);

  // The current member reads the plaintext…
  const legit = grab(result, /(\w+) \(current member\): “([^”]+)” ✓/);
  expect(state.members).toContain(legit[1]);
  expect(legit[2]).toBe('Meet at the safe house at 21:00.');

  // …and the removed member's stale secret fails AEAD authentication.
  expect(result).toContain('Bob (removed): 🔒 AEAD authentication failed — locked out ✓');
  expect(result, 'a readable plaintext for the removed member would be a failure').not.toContain(
    'should be locked out',
  );
});

test('send: the transcript records the epoch, generation and ciphertext size of the real message', async ({
  page,
}) => {
  await open(page);

  const message = 'transfer=42&to=bob';
  await page.locator('#msg-input-leaf-0').fill(message);
  await page.getByRole('button', { name: /Send an encrypted message from Alice \(leaf 0\)/ }).click();
  await expect(page.locator('.transcript-item').first()).toContainText('APPLICATION');

  const state = await banner(page);
  const entry = await flat(page.locator('.transcript-item').first());
  const head = grab(entry, /APPLICATION • epoch (\d+) • gen (\d+) • (\w+) \(leaf (\d+)\)/);
  expect(Number(head[1])).toBe(state.epoch);
  expect(Number(head[2])).toBe(1); // first message from this ratchet
  expect(head[3]).toBe('Alice');
  expect(head[4]).toBe('0');
  expect(entry).toContain(`Alice → group: ${message}`);

  // A real AES-GCM seal: 16-byte tag, and the ciphertext is the plaintext plus
  // that tag.
  expect(grab(entry, /AEAD tag: ([0-9a-f]{32})/)[1]).toHaveLength(32);
  const ctBytes = Number(grab(entry, /ciphertext: [0-9a-f]{24}… \((\d+)B\)/)[1]);
  expect(ctBytes).toBe(message.length + 16);

  // Sending does not roll the epoch — only commits do.
  await page.locator('#msg-input-leaf-0').fill('second');
  await page.getByRole('button', { name: /Send an encrypted message from Alice \(leaf 0\)/ }).click();
  await expect(page.locator('.transcript-item').first()).toContainText('second');
  const next = await banner(page);
  expect(next.epoch).toBe(state.epoch);
  // The ratchet advanced, so the generation did too.
  expect(
    Number(grab(await flat(page.locator('.transcript-item').first()), /gen (\d+)/)[1]),
  ).toBe(2);
});

test('tree inspector: selecting a leaf names exactly the nodes that member can derive', async ({
  page,
}) => {
  await open(page);

  const tree = panel(page, 'Ratchet Tree');
  await page.locator('#tree-node-0').click();
  await expect(tree).toContainText('Alice · leaf 0');

  const detail = await flat(tree);
  const derivable = grab(detail, /every node on its direct path: nodes? ([\d, ]+) \(highlighted\)/)[1]!
    .split(', ')
    .map(Number);
  expect(derivable.length).toBeGreaterThan(0);
  expect(detail).toContain('Everything else in the tree is dimmed — Alice is blind to it');
  expect(detail).toMatch(/HPKE public key: [0-9a-f]{16}…/);

  // Each named node exists in the tree and is not the leaf itself.
  for (const node of derivable) {
    expect(node).not.toBe(0);
    await expect(page.locator(`#tree-node-${node}`)).toHaveCount(1);
  }

  // Selecting again clears the selection.
  await page.locator('#tree-node-0').click();
  await expect(tree).not.toContainText('Alice · leaf 0');

  // A parent node reports who can derive it, not a member identity.
  await page.locator(`#tree-node-${derivable[0]}`).click();
  await expect(tree).toContainText(`node ${derivable[0]}`);
});

test('guided tour: the nine steps run the whole lifecycle and leave everything revealed', async ({
  page,
}) => {
  await open(page);

  const titles = [
    'Welcome to the MLS Group Lab',
    'Add a member',
    'Send a message',
    'Re-key with an Update',
    'Everyone agrees on the new secret',
    'Remove a member',
    'The removed member is locked out',
    'Heal a compromise',
    'That is the whole lifecycle',
  ];

  await page.getByRole('button', { name: /Start the guided tour/ }).click();
  await expect(page.locator('.tour-card')).toHaveCount(1);

  // Only these steps commit, so only these may advance the epoch.
  const commits = new Set(['Add a member', 'Re-key with an Update', 'Remove a member', 'Heal a compromise']);

  for (let step = 0; step < titles.length; step += 1) {
    await expect(page.locator('.tour-meta')).toHaveText(
      `Guided tour · step ${step + 1} of ${titles.length}`,
    );
    await expect(page.locator('.tour-title')).toHaveText(titles[step]!);

    const before = await banner(page);
    await page.locator('.tour-controls button').first().click();
    if (step < titles.length - 1) {
      await expect(page.locator('.tour-title')).toHaveText(titles[step + 1]!);
    }
    const after = await banner(page);
    expect(
      after.epoch,
      `step "${titles[step]}" ${commits.has(titles[step]!) ? 'must' : 'must not'} advance the epoch`,
    ).toBe(before.epoch + (commits.has(titles[step]!) ? 1 : 0));
  }

  // The tour closes itself and hands over the whole lab.
  await expect(page.locator('.tour-card')).toHaveCount(0);
  await expect(page.locator('section.panel-locked')).toHaveCount(0);

  const end = await banner(page);
  expect(end.epoch).toBe(4); // add, update, remove, PCS heal
  expect(end.members).toEqual(['Alice', 'Bob', 'Charlie']); // Dave joined then was removed

  // The panels the tour ran are populated, not just unlocked.
  await expect(panel(page, 'TreeKEM Convergence')).toContainText(
    'independently derived the same root secret',
  );
  await expect(panel(page, 'Access Control: Removed Member')).toContainText('locked out ✓');
  await expect(panel(page, 'PCS Recovery Walkthrough')).toContainText('Attacker locked out ✓');
});
