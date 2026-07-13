import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

/**
 * WCAG regression gate. Deploys are already gated on the NIST/RFC 9420 KAT
 * vectors; this gates them on accessibility the same way. Scans the full page
 * with every <details> expanded and every collapsible/hidden region revealed,
 * in both themes (dark default + light).
 */

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

async function revealEverything(page: Page): Promise<void> {
  // Progressive disclosure hides the advanced panels behind teasers on first
  // load. Reveal them all so axe scans their contents (tables, chips, readouts)
  // in both themes — otherwise the gate would shrink a11y coverage.
  const revealAll = page.getByRole('button', { name: 'Reveal all advanced panels at once' });
  if (await revealAll.count()) {
    await revealAll.click();
  }
  // Run the proof panels' actions so their output regions (convergence table,
  // access-control verdict) actually render and get scanned. Select a member
  // leaf too, so the tree selection readout is on screen.
  const runButtons = [
    /Independently derive the root secret/i,
    /Send a secret in epoch/i,
    /Capture .*current message key/i,
  ];
  for (const re of runButtons) {
    const b = page.getByRole('button', { name: re });
    if (await b.count()) await b.first().click();
  }
  const leaf0 = page.locator('#tree-node-0');
  if (await leaf0.count()) await leaf0.click();

  // Neutralize animations/transitions/opacity so nothing is mid-fade when axe
  // measures contrast (mid-fade opacity produces phantom contrast failures).
  await page.addStyleTag({
    content: `*,*::before,*::after{animation:none!important;transition:none!important}
      [hidden]{opacity:1!important}`,
  });

  await page.evaluate(() => {
    // Expand every native <details>.
    for (const details of Array.from(document.querySelectorAll('details'))) {
      (details as HTMLDetailsElement).open = true;
    }
    // Reveal anything the app hides via the [hidden] attribute.
    for (const el of Array.from(document.querySelectorAll('[hidden]'))) {
      el.removeAttribute('hidden');
    }
  });
}

async function scan(page: Page): Promise<void> {
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const summary = results.violations.map((v) => ({
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5),
  }));
  expect(summary).toEqual([]);
}

test('no WCAG A/AA violations in dark theme', async ({ page }) => {
  await page.goto('.');
  await revealEverything(page);
  await scan(page);
});

test('no WCAG A/AA violations in light theme', async ({ page }) => {
  await page.goto('.');
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await revealEverything(page);
  await scan(page);
});
