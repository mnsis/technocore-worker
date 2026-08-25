import { expect, test } from "@playwright/test";

const enabled = process.env.TC_E2E === "1";
const passphrase = "phase3a-local-e2e-only-passphrase";
const pemPath = "/tmp/technocore-browser-e2e-identity.pem";

test("one controlled live contribution-verify exchange", async ({ page }) => {
  test.skip(!enabled, "Set TC_E2E=1 only for the single controlled live run.");
  test.setTimeout(180000);
  await page.goto("/");
  await page.locator("#new-passphrase").fill(passphrase);
  await page.locator("#confirm-passphrase").fill(passphrase);
  await page.locator("#create").click();
  await expect(page.locator("#status")).toHaveText("Identity ready");
  const did = await page.locator("#did").textContent();
  const downloadPromise = page.waitForEvent("download");
  await page.locator("#download").click();
  await (await downloadPromise).saveAs(pemPath);
  await import("node:fs").then(({ chmodSync }) => chmodSync(pemPath, 0o600));
  await page.locator("#repository").fill("paiin-arc/technocore-beginner-guide");
  await page.locator("#commit").fill("93dab08e185121186d009f9b637a37365c294ea1");
  await page.locator("#send").click();
  await expect(page.locator("#status")).toHaveText("Result received", { timeout: 160000 });
  const result = JSON.parse(await page.locator("#result").textContent());
  expect(result.worker).toBe("did:key:z6MkktyZ4gpSR62gfvh71yKBonTCvqEgBt9mmiaXLPNH8djM");
  expect(result.checks.repository.status).toBe("CONFIRMED");
  expect(result.checks.commit.status).toBe("CONFIRMED");
  await import("node:fs").then(({ writeFileSync }) => writeFileSync(
    "/tmp/technocore-browser-e2e-result.json",
    JSON.stringify({ did, worker: result.worker, status: result.status, checks: result.checks }),
    { mode: 0o600 },
  ));
});
