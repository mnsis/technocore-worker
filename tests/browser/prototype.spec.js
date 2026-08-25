import { createHash } from "node:crypto";
import { expect, test } from "@playwright/test";

const PASSPHRASE = "headless compatibility passphrase";
const WORKER_DID = "did:key:z6MkktyZ4gpSR62gfvh71yKBonTCvqEgBt9mmiaXLPNH8djM";
async function createIdentity(page) {
  await page.goto("/"); await page.locator("#new-passphrase").fill(PASSPHRASE); await page.locator("#confirm-passphrase").fill(PASSPHRASE); await page.locator("#create").click();
  await expect(page.locator("#status")).toHaveText("Identity ready"); return page.locator("#did").textContent();
}
async function prove(page) { await page.locator("#prove").click(); await expect(page.locator("#proof-result")).toHaveText("✓ DID control demonstrated"); }

test("gates checking on proof and valid fields with inline errors", async ({ page }) => {
  await page.goto("/"); await expect(page.locator("#send")).toBeDisabled();
  await page.locator("#new-passphrase").fill(PASSPHRASE); await page.locator("#confirm-passphrase").fill(PASSPHRASE); await page.locator("#create").click(); await expect(page.locator("#status")).toHaveText("Identity ready");
  await prove(page); await expect(page.locator("#prove")).toBeHidden(); await expect(page.locator("#send")).toBeDisabled();
  await page.locator("#repository").fill("invalid repository"); await expect(page.locator("#repository-error")).toHaveText("Use owner/repository format."); await expect(page.locator("#status")).toHaveText("DID control demonstrated"); await expect(page.locator("#send")).toBeDisabled();
  await page.locator("#repository").fill("owner/repository"); await page.locator("#commit").fill("abc123"); await expect(page.locator("#commit-error")).toHaveText("Enter the full 40-character commit SHA."); await expect(page.locator("#send")).toBeDisabled();
  await page.locator("#send").evaluate((button) => { button.disabled = false; button.form.requestSubmit(); }); await expect(page.locator("#progress .active")).toHaveCount(0); await expect(page.locator("#status")).toHaveText("DID control demonstrated");
  await page.locator("#example").click(); await expect(page.locator("#repository")).toHaveValue("paiin-arc/technocore-beginner-guide"); await expect(page.locator("#commit")).toHaveValue("93dab08e185121186d009f9b637a37365c294ea1"); await expect(page.locator("#path")).toHaveValue(""); await expect(page.locator("#send")).toBeEnabled();
});

test("creates, downloads, proves control, protects network data, and clears on reload", async ({ page }) => {
  await page.addInitScript(() => { const original = URL.revokeObjectURL.bind(URL); window.__revokedPemUrls = []; URL.revokeObjectURL = (value) => { window.__revokedPemUrls.push(value); original(value); }; });
  const requests = []; page.on("request", (request) => requests.push({ url: request.url(), data: request.postData() }));
  const response = await page.goto("/"); expect(response.headers()["content-security-policy"]).toContain("connect-src 'self'"); expect(response.headers()["x-frame-options"]).toBe("DENY");
  const did = await createIdentity(page); expect(did).toMatch(/^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]{44}$/);
  const downloadPromise = page.waitForEvent("download"); await page.locator("#download").click(); const pem = await (await downloadPromise).createReadStream().then(async (stream) => { let value = ""; for await (const part of stream) value += part; return value; });
  expect(pem).toMatch(/^-----BEGIN ENCRYPTED PRIVATE KEY-----/); expect(pem).not.toContain("BEGIN PRIVATE KEY"); await expect.poll(() => page.evaluate(() => window.__revokedPemUrls.length)).toBe(1);
  await prove(page); for (const request of requests) { expect(request.url).toMatch(/^http:\/\/127\.0\.0\.1:18787\//); expect(request.data || "").not.toContain(PASSPHRASE); expect(request.data || "").not.toContain("PRIVATE KEY"); }
  expect(await page.evaluate(() => ({ local: localStorage.length, session: sessionStorage.length, databases: indexedDB.databases ? indexedDB.databases() : [] }))).toMatchObject({ local: 0, session: 0 });
  await page.reload(); await expect(page.locator("#identity-ready")).toBeHidden(); await expect(page.locator("#send")).toBeDisabled();
});

test("imports PEM, rejects wrong password, validates inputs, optional path, and renders result", async ({ page }) => {
  await createIdentity(page); const downloadPromise = page.waitForEvent("download"); await page.locator("#download").click(); const pemPath = await (await downloadPromise).path(); await page.reload();
  await page.locator("#show-import").click(); await page.locator("#pem-file").setInputFiles(pemPath); await page.locator("#import-passphrase").fill("wrong password here"); await page.locator("#import").click(); await expect(page.locator("#status")).toContainText("Incorrect passphrase");
  await page.locator("#import-passphrase").fill(PASSPHRASE); await page.locator("#import").click(); await expect(page.locator("#status")).toHaveText("Identity ready"); const did = await page.locator("#did").textContent(); await prove(page);
  await page.locator("#repository").fill("bad repository"); await page.locator("#commit").fill("short"); await expect(page.locator("#repository-error")).toBeVisible(); await expect(page.locator("#commit-error")).toBeVisible(); await expect(page.locator("#status")).toHaveText("DID control demonstrated");
  let expected; await page.route("**/api/technocore/request", async (route) => { const body = route.request().postDataJSON(); const request = JSON.parse(body.text); expect(request.path).toBe("README.md"); expected = { request, hash: createHash("sha256").update(body.text).digest("hex") }; await route.fulfill({ json: { posted: { seq: 7, from: did, text: body.text } } }); });
  await page.route("**/api/technocore/reply?*", async (route) => route.fulfill({ json: { room: expected.request.reply, last_seq: 1, messages: [{ from: WORKER_DID, text: JSON.stringify({ capability: "contribution-verify", checks: { repository: { status: "CONFIRMED" }, commit: { status: "CONFIRMED" }, requested_file: { status: "CONFIRMED" } }, job: expected.request.job, request: { did, room: "mb-technocore-worker", sha256: expected.hash }, status: "completed", v: "tc-worker/v1", worker: WORKER_DID }) }] } }));
  await page.locator("#repository").fill("paiin-arc/technocore-beginner-guide"); await page.locator("#commit").fill("93dab08e185121186d009f9b637a37365c294ea1"); await page.locator("#path").fill("README.md"); await page.locator("#send").click();
  await expect(page.locator("#status")).toHaveText("Response received"); await expect(page.locator("#result-worker")).toHaveText(WORKER_DID); await expect(page.locator("#result-requester")).toHaveText(did); await expect(page.locator("#result-file")).toHaveText("CONFIRMED");
});

test("renders UNAVAILABLE without calling it a failure and exposes source metadata", async ({ page }) => {
  await page.route("**/api/meta", (route) => route.fulfill({ json: { commit: "a".repeat(40) } })); await createIdentity(page); await prove(page);
  const did = await page.locator("#did").textContent(); let expected; await page.route("**/api/technocore/request", async (route) => { const body = route.request().postDataJSON(); expected = { request: JSON.parse(body.text), hash: createHash("sha256").update(body.text).digest("hex") }; await route.fulfill({ json: { posted: { seq: 1, from: did, text: body.text } } }); });
  await page.route("**/api/technocore/reply?*", (route) => route.fulfill({ json: { room: expected.request.reply, messages: [{ from: WORKER_DID, text: JSON.stringify({ capability: "contribution-verify", checks: { repository: { status: "UNAVAILABLE" }, commit: { status: "UNAVAILABLE" }, requested_file: { status: "NOT_CHECKED" } }, job: expected.request.job, request: { did, room: "mb-technocore-worker", sha256: expected.hash }, status: "completed", v: "tc-worker/v1", worker: WORKER_DID }) }] } }));
  await page.locator("#example").click(); page.once("dialog", (dialog) => dialog.accept()); await page.locator("#send").click(); await expect(page.locator("#result-repository")).toHaveText("UNAVAILABLE"); await expect(page.locator("body")).not.toContainText("VERIFIED");
  await expect(page.locator("#served-commit")).toHaveText("a".repeat(40)); await expect(page.locator(`footer code:has-text("${WORKER_DID}")`)).toBeVisible(); expect(await page.locator('a[href="https://x.com/amjawaeth"]').count()).toBe(1); expect(await page.locator('a[href="https://x.com/flop_labs"]').count()).toBe(1);
});

test("mobile layout fits and JavaScript-disabled message is useful", async ({ browser }) => {
  const mobileContext = await browser.newContext({ viewport: { width: 375, height: 812 } }); const mobile = await mobileContext.newPage(); await mobile.goto("/"); expect(await mobile.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true); await mobileContext.close();
  const noJs = await browser.newContext({ javaScriptEnabled: false }); const page = await noJs.newPage(); await page.goto("/"); await expect(page.locator(".noscript")).toContainText("identity creation and signing happen locally"); await noJs.close();
});
