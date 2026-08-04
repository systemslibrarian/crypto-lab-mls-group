import { expect, test } from '@playwright/test';

function channel(value: number): number {
  const s = value / 255;
  return s <= 0.04045 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
}

function luminance(rgb: string): number {
  const [r, g, b] = rgb.match(/[\d.]+/g)!.slice(0, 3).map(Number);
  return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b);
}

function contrast(a: string, b: string): number {
  const [lighter, darker] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (lighter + 0.05) / (darker + 0.05);
}

for (const theme of ['dark', 'light'] as const) {
  test(`text input boundary clears 3:1 in ${theme} theme`, async ({ page }) => {
    await page.goto('.');
    if (theme === 'light') await page.locator('#cl-theme-toggle').click();
    // The inputs carry `transition: all .15s`, so a single read right after the
    // theme flip samples an interpolated colour part-way between the two themes
    // and scores whatever the machine happened to be mid-fade. Poll until the
    // transition settles; a genuinely failing settled colour still times out here.
    await expect
      .poll(async () =>
        contrast(
          ...(await page.locator('input[type="text"]').first().evaluate((element) => {
            const style = getComputedStyle(element);
            return [style.borderTopColor, style.backgroundColor] as [string, string];
          }))
        )
      )
      .toBeGreaterThanOrEqual(3);
  });
}
