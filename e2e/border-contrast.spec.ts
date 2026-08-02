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
    const colors = await page.locator('input[type="text"]').first().evaluate((element) => {
      const style = getComputedStyle(element);
      return { border: style.borderTopColor, background: style.backgroundColor };
    });
    expect(contrast(colors.border, colors.background)).toBeGreaterThanOrEqual(3);
  });
}
