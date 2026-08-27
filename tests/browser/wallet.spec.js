import { createHash } from "node:crypto";
import { expect, test } from "@playwright/test";

const WORKER_DID = "did:key:z6MkktyZ4gpSR62gfvh71yKBonTCvqEgBt9mmiaXLPNH8djM";
const PASSPHRASE = "wallet isolation test passphrase";

async function mnemonic(page) {
  return page.locator("#wallet-phrase-list strong").allTextContents().then((words) => words.join(" "));
}

async function reveal(page) {
  await page.locator("#wallet-reveal").click(); await expect(page.locator("#wallet-confirm-reveal")).toBeDisabled(); await page.locator("#wallet-acknowledge").check(); await page.locator("#wallet-confirm-reveal").click(); await expect(page.locator("#wallet-phrase-list li")).toHaveCount(12);
}

test("creates a standard local EVM wallet without persistence or network activity", async ({ page, context }) => {
  await page.addInitScript(() => { Math.random = () => { throw new Error("Math.random must not be used"); }; window.__copied = null; Object.defineProperty(navigator, "clipboard", { value: { writeText: async (value) => { window.__copied = value; } }, configurable: true }); });
  const requests = []; page.on("request", (request) => requests.push({ url: request.url(), body: request.postData() || "" }));
  await page.goto("/"); await expect(page.locator("#wallet-ready")).toBeHidden(); await expect(page.locator("#wallet-create")).toBeVisible(); const loadedRequests = requests.length;
  await page.locator("#wallet-create").click(); await expect(page.locator("#wallet-ready")).toBeVisible(); await expect(page.locator("#wallet-phrase")).toBeHidden(); await expect(page.locator("#wallet-phrase-list li")).toHaveCount(0); await expect(page.locator("#wallet-reveal-confirm")).toBeHidden(); expect(requests).toHaveLength(loadedRequests);
  const firstAddress = await page.locator("#wallet-address").textContent(); expect(firstAddress).toMatch(/^0x[0-9a-fA-F]{40}$/); expect(await page.evaluate(async (address) => { const wallet = await import("/wallet.js"); return wallet.checksumAddress(address.slice(2)) === address; }, firstAddress)).toBe(true);
  await page.locator("#wallet-copy-address").click(); expect(await page.evaluate(() => window.__copied)).toBe(firstAddress);
  await reveal(page); const firstMnemonic = await mnemonic(page); expect(firstMnemonic.split(" ")).toHaveLength(12); expect(await page.evaluate(async (value) => { const wallet = await import("/wallet.js"); return { bits: wallet.mnemonicEntropyBits(value), path: wallet.EVM_DERIVATION_PATH, keys: Object.keys(wallet.walletFromMnemonic(value)).sort() }; }, firstMnemonic)).toEqual({ bits: 128, path: "m/44'/60'/0'/0/0", keys: ["address", "mnemonic", "path"] });
  await expect(page.locator("#wallet-visibility")).toHaveText("Visible"); await page.locator("#wallet-copy-phrase").click(); expect(await page.evaluate(() => window.__copied)).toBe(firstMnemonic); await page.locator("#wallet-saved").click(); await expect(page.locator("#wallet-phrase")).toBeHidden(); await expect(page.locator("#wallet-visibility")).toHaveText("Hidden"); await expect(page.locator("#wallet-saved-state")).toBeVisible();
  page.once("dialog", (dialog) => dialog.dismiss()); await page.locator("#wallet-create-another").click(); await expect(page.locator("#wallet-address")).toHaveText(firstAddress);
  page.once("dialog", (dialog) => dialog.accept()); await page.locator("#wallet-create-another").click(); const secondAddress = await page.locator("#wallet-address").textContent(); expect(secondAddress).not.toBe(firstAddress); expect(requests).toHaveLength(loadedRequests);
  expect(await page.evaluate(() => ({ local: localStorage.length, session: sessionStorage.length, url: location.href, databases: indexedDB.databases ? indexedDB.databases() : [] }))).toMatchObject({ local: 0, session: 0, url: "http://127.0.0.1:18787/" });
  const cookies = await context.cookies(); expect(JSON.stringify(cookies)).not.toContain(firstMnemonic); expect(JSON.stringify(cookies)).not.toContain(firstAddress); expect(requests.every(({ url, body }) => new URL(url).origin === "http://127.0.0.1:18787" && !body.includes(firstMnemonic) && !body.includes(firstAddress))).toBe(true);
  await page.reload(); await expect(page.locator("#wallet-ready")).toBeHidden(); await expect(page.locator("#wallet-create")).toBeVisible();
});

test("matches the standard EVM mnemonic and derivation vector", async ({ page }) => {
  await page.goto("/"); const result = await page.evaluate(async () => { const wallet = await import("/wallet.js"); return wallet.walletFromMnemonic("test test test test test test test test test test test junk"); });
  expect(result).toEqual({ mnemonic: "test test test test test test test test test test test junk", address: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266", path: "m/44'/60'/0'/0/0" });
});

test("wallet secrets remain isolated from Technocore and receipt surfaces", async ({ page, browserName }) => {
  test.skip(browserName !== "chromium", "Cross-surface isolation is browser-independent.");
  await page.addInitScript(() => { window.__copied = null; window.__opened = null; window.__canvasText = []; Object.defineProperty(navigator, "clipboard", { value: { writeText: async (value) => { window.__copied = value; } }, configurable: true }); window.open = (url) => { window.__opened = url; return null; }; const original = CanvasRenderingContext2D.prototype.fillText; CanvasRenderingContext2D.prototype.fillText = function (...args) { window.__canvasText.push(String(args[0])); return original.apply(this, args); }; });
  const traffic = []; page.on("request", (request) => traffic.push(`${request.url()}\n${request.postData() || ""}`)); await page.goto("/"); await page.locator("#wallet-create").click(); await reveal(page); const secret = await mnemonic(page); const address = await page.locator("#wallet-address").textContent();
  await page.route("**/api/challenge", (route) => route.fulfill({ json: { challenge: "isolated-wallet-test", payload: "isolated wallet test challenge", expires_at: 4102444800 } })); await page.route("**/api/challenge/verify", (route) => route.fulfill({ json: { demonstrated: true } }));
  await page.locator("#new-passphrase").fill(PASSPHRASE); await page.locator("#create").click(); await expect(page.locator("#proof-result")).toHaveText("DID control demonstrated"); const did = await page.locator("#did").textContent(); let expected;
  await page.route("**/api/reply-baseline", (route) => route.fulfill({ json: { reply_after: 4 } })); await page.route("**/api/technocore/request", async (route) => { const body = route.request().postDataJSON(); expected = { request: JSON.parse(body.text), hash: createHash("sha256").update(body.text).digest("hex") }; expect(body.text).not.toContain(secret); expect(body.text).not.toContain(address); await route.fulfill({ json: { posted: { seq: 9, from: did, text: body.text } } }); });
  await page.route("**/api/jobs/**", (route) => route.fulfill({ json: { result: { capability: "contribution-verify", checks: { repository: { status: "CONFIRMED" }, commit: { status: "CONFIRMED" }, requested_file: { status: "NOT_CHECKED" } }, job: expected.request.job, request: { did, room: "mb-technocore-worker", seq: 9, sha256: expected.hash, reply_after: 4 }, status: "completed", v: "tc-worker/v2", worker: WORKER_DID } } }));
  await page.locator("#example").click(); page.once("dialog", (dialog) => dialog.accept()); await page.locator("#send").click(); await expect(page.locator("#shareable-receipt")).toBeVisible(); await page.locator("#copy-receipt").click(); expect(await page.evaluate(() => window.__copied)).not.toContain(secret); expect(await page.evaluate(() => window.__copied)).not.toContain(address); await page.locator("#share-x").click(); expect(await page.evaluate(() => window.__opened)).not.toContain(secret); expect(await page.evaluate(() => window.__opened)).not.toContain(address);
  const download = page.waitForEvent("download"); await page.locator("#download-receipt").click(); await download; const canvas = await page.evaluate(() => window.__canvasText.join("\n")); expect(canvas).not.toContain(secret); expect(canvas).not.toContain(address); expect(traffic.join("\n")).not.toContain(secret); expect(traffic.join("\n")).not.toContain(address);
});

test("hides the recovery phrase on explicit hide and on losing reveal context", async ({ page }) => {
  await page.goto("/");
  await page.locator("#wallet-create").click();
  await reveal(page);
  await expect(page.locator("#wallet-visibility")).toHaveText("Visible");

  await page.locator("#wallet-hide").click();
  await expect(page.locator("#wallet-phrase")).toBeHidden();
  await expect(page.locator("#wallet-phrase-list li")).toHaveCount(0);
  await expect(page.locator("#wallet-visibility")).toHaveText("Hidden");
  await expect(page.locator("#wallet-reveal")).toBeVisible();

  await page.locator("#wallet-reveal").click();
  await expect(page.locator("#wallet-confirm-reveal")).toBeDisabled();
  await page.locator("#wallet-acknowledge").check();
  await page.locator("#wallet-confirm-reveal").click();
  await expect(page.locator("#wallet-phrase-list li")).toHaveCount(12);

  await page.locator("#new-passphrase").click();
  await expect(page.locator("#wallet-phrase")).toBeHidden();
  await expect(page.locator("#wallet-phrase-list li")).toHaveCount(0);
  await expect(page.locator("#wallet-acknowledge")).not.toBeChecked();
  await expect(page.locator("#wallet-address")).toBeVisible();
});

test("wallet controls fit a 390px viewport", async ({ browser }) => {
  const context = await browser.newContext({ viewport: { width: 390, height: 844 } }); const page = await context.newPage(); await page.goto("/"); await page.locator("#wallet-create").click(); await reveal(page); expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true); await expect(page.locator("#wallet-address")).toBeVisible(); await expect(page.locator("#wallet-phrase-list li")).toHaveCount(12); await context.close();
});
