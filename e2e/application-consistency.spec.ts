import {test,expect} from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
test('authenticated poll disagreement stays separate from shared keys',async({page})=>{
  await page.goto('./');
  await page.locator('#app-compare').click();
  await expect(page.locator('#app-result')).toContainText('Equal epoch keys: true');
  await expect(page.locator('#app-result')).toContainText('All decryptions and sender signatures valid: true');
  await expect(page.locator('#app-result')).toContainText('Message sets equal: false');
  await expect(page.locator('#app-result')).toContainText('Full poll-bound responses equal: false');
  await page.locator('#app-scenario').selectOption('honest');await page.locator('#app-compare').click();
  await expect(page.locator('#app-result')).toContainText('Same edit set and reconciled document: true');
  await page.locator('#app-scenario').selectOption('missing');await page.locator('#app-compare').click();
  await expect(page.locator('#app-result')).toContainText('Same edit set and reconciled document: false');
  const results=await new AxeBuilder({page}).include('[aria-labelledby="app-consistency-title"]').withTags(['wcag2a','wcag2aa','wcag21aa']).analyze();
  expect(results.violations).toEqual([]);
});
