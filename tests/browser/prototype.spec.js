import { createHash } from "node:crypto";
import { expect, test } from "@playwright/test";

const PASSPHRASE = "headless compatibility passphrase";
const WORKER_DID = "did:key:z6MkktyZ4gpSR62gfvh71yKBonTCvqEgBt9mmiaXLPNH8djM";
async function createIdentity(page) {
  await page.goto("/"); await page.locator("#new-passphrase").fill(PASSPHRASE); await page.locator("#confirm-passphrase").fill(PASSPHRASE); await page.locator("#create").click();
  await expect(page.locator("#proof-result")).toHaveText("DID control demonstrated", { timeout: 15000 }); return page.locator("#did").textContent();
}

async function mockV2Reply(page, did, checks, { baseline = 12, sequence = 7, wait = false } = {}) {
  let expected;
  let releaseReply;
  await page.route("**/api/reply-baseline", (route) => route.fulfill({ json: { reply_after: baseline } }));
  await page.route("**/api/technocore/request", async (route) => {
    const body = route.request().postDataJSON(); const request = JSON.parse(body.text);
    expect(request.v).toBe("tc-worker/v2"); expect(request.reply_after).toBe(baseline); expect(request).not.toHaveProperty("reply");
    expected = { request, hash: createHash("sha256").update(body.text).digest("hex") };
    await route.fulfill({ json: { posted: { seq: sequence, from: did, text: body.text } } });
  });
  await page.route("**/api/jobs/**", async (route) => {
    if (wait) await new Promise((resolve) => { releaseReply = resolve; });
    await route.fulfill({ json: { result: { capability: "contribution-verify", checks, job: expected.request.job,
      request: { did, room: "mb-technocore-worker", seq: sequence, sha256: expected.hash, reply_after: baseline },
      status: "completed", v: "tc-worker/v2", worker: WORKER_DID } } });
  });
  return () => releaseReply?.();
}

test("gates checking on proof and valid fields with inline errors", async ({ page }) => {
  await page.goto("/"); await expect(page.locator("#send")).toBeDisabled();
  await page.locator("#new-passphrase").fill(PASSPHRASE); await page.locator("#confirm-passphrase").fill(PASSPHRASE); await page.locator("#create").click(); await expect(page.locator("#proof-result")).toHaveText("DID control demonstrated");
  await expect(page.locator("#identity-setup")).toBeHidden(); await expect(page.locator("#identity-ready")).toBeVisible(); await expect(page.locator("#control-stage")).toHaveClass(/completed/); await expect(page.locator("#prove")).toBeHidden(); await expect(page.locator("#send")).toBeDisabled();
  await page.locator("#repository").fill("invalid repository"); await expect(page.locator("#repository-error")).toHaveText("Use owner/repository format."); await expect(page.locator("#status")).toHaveText("DID control demonstrated"); await expect(page.locator("#send")).toBeDisabled();
  await page.locator("#repository").fill("owner/repository"); await page.locator("#commit").fill("abc123"); await expect(page.locator("#commit-error")).toHaveText("Enter the full 40-character commit SHA."); await expect(page.locator("#send")).toBeDisabled();
  await page.locator("#send").evaluate((button) => { button.disabled = false; button.form.requestSubmit(); }); await expect(page.locator("#execution .active")).toHaveCount(0); await expect(page.locator("#status")).toHaveText("DID control demonstrated");
  await page.locator("#example").click(); await expect(page.locator("#repository")).toHaveValue("paiin-arc/technocore-beginner-guide"); await expect(page.locator("#commit")).toHaveValue("93dab08e185121186d009f9b637a37365c294ea1"); await expect(page.locator("#path")).toHaveValue(""); await expect(page.locator("#send")).toBeEnabled();
});

test("creates, downloads, proves control, protects network data, and clears on reload", async ({ page }) => {
  await page.addInitScript(() => { const original = URL.revokeObjectURL.bind(URL); window.__revokedPemUrls = []; URL.revokeObjectURL = (value) => { window.__revokedPemUrls.push(value); original(value); }; });
  const requests = []; page.on("request", (request) => requests.push({ url: request.url(), data: request.postData() }));
  const response = await page.goto("/"); expect(response.headers()["content-security-policy"]).toContain("connect-src 'self'"); expect(response.headers()["x-frame-options"]).toBe("DENY");
  const did = await createIdentity(page); expect(did).toMatch(/^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]{44}$/);
  const downloadPromise = page.waitForEvent("download"); await page.locator("#download").click(); const pem = await (await downloadPromise).createReadStream().then(async (stream) => { let value = ""; for await (const part of stream) value += part; return value; });
  expect(pem).toMatch(/^-----BEGIN ENCRYPTED PRIVATE KEY-----/); expect(pem).not.toContain("BEGIN PRIVATE KEY"); await expect.poll(() => page.evaluate(() => window.__revokedPemUrls.length)).toBe(1); await expect(page.locator("#backup-note")).toHaveText("✓ Encrypted backup downloaded"); await expect(page.locator("#download")).toBeHidden();
  for (const request of requests) { expect(request.url).toMatch(/^http:\/\/127\.0\.0\.1:18787\//); expect(request.data || "").not.toContain(PASSPHRASE); expect(request.data || "").not.toContain("PRIVATE KEY"); }
  expect(await page.evaluate(() => ({ local: localStorage.length, session: sessionStorage.length, databases: indexedDB.databases ? indexedDB.databases() : [] }))).toMatchObject({ local: 0, session: 0 });
  await page.reload(); await expect(page.locator("#identity-ready")).toBeHidden(); await expect(page.locator("#send")).toBeDisabled();
});

test("imports PEM, rejects wrong password, validates inputs, optional path, and renders result", async ({ page }) => {
  await createIdentity(page); const downloadPromise = page.waitForEvent("download"); await page.locator("#download").click(); const pemPath = await (await downloadPromise).path(); await page.reload();
  await page.locator("#show-import").click(); await page.locator("#pem-file").setInputFiles(pemPath); await page.locator("#import-passphrase").fill("wrong password here"); await page.locator("#import").click(); await expect(page.locator("#status")).toContainText("Incorrect passphrase");
  await page.locator("#import-passphrase").fill(PASSPHRASE); await page.locator("#import").click(); await expect(page.locator("#proof-result")).toHaveText("DID control demonstrated"); const did = await page.locator("#did").textContent();
  await page.locator("#repository").fill("bad repository"); await page.locator("#commit").fill("short"); await expect(page.locator("#repository-error")).toBeVisible(); await expect(page.locator("#commit-error")).toBeVisible(); await expect(page.locator("#status")).toHaveText("DID control demonstrated");
  const releaseReply = await mockV2Reply(page, did, { repository: { status: "CONFIRMED" }, commit: { status: "CONFIRMED" }, requested_file: { status: "CONFIRMED" } }, { wait: true });
  await page.locator("#repository").fill("paiin-arc/technocore-beginner-guide"); await page.locator("#commit").fill("93dab08e185121186d009f9b637a37365c294ea1"); await page.locator("#path").fill("README.md"); await page.locator("#send").click(); await expect(page.locator("#checking")).toBeVisible(); await expect(page.locator("#github-form-wrap")).toBeHidden(); await expect(page.locator(".activity")).toBeVisible(); await expect(page.locator('[data-stage="github"]')).toHaveClass(/completed/); await expect(page.locator('[data-stage="result"]')).toHaveClass(/current/); await expect(page.locator("#download")).toHaveText("Download backup"); const firstElapsed = await page.locator("#waiting-elapsed").textContent(); await page.waitForTimeout(350); expect(await page.locator("#waiting-elapsed").textContent()).not.toBe(firstElapsed); releaseReply();
  await expect(page.locator("#status")).toHaveText("Response received"); const stoppedElapsed = await page.locator("#waiting-elapsed").textContent(); await page.waitForTimeout(250); expect(await page.locator("#waiting-elapsed").textContent()).toBe(stoppedElapsed); await expect(page.locator("#result-stage")).toBeVisible(); await expect(page.locator("#checking")).toBeHidden(); await expect(page.locator("#github-stage")).toBeHidden(); await expect(page.locator("#result-worker")).toHaveText(WORKER_DID); await expect(page.locator("#result-requester")).toHaveText(did); await expect(page.locator("#result-file")).toHaveText("CONFIRMED"); await expect(page.locator("#result-file")).toHaveClass("confirmed");
  await page.locator("#check-another").click(); await expect(page.locator("#github-form-wrap")).toBeVisible(); await expect(page.locator("#did")).toHaveText(did); await expect(page.locator("#identity-setup")).toBeHidden();
});

test("renders a shareable receipt and exposes source metadata", async ({ page }) => {
  await page.addInitScript(() => {
    window.__copied = null; window.__opened = null; window.__canvasText = [];
    Object.defineProperty(navigator, "clipboard", { value: { writeText: async (value) => { window.__copied = value; } }, configurable: true });
    window.open = (url) => { window.__opened = url; return null; };
    const original = CanvasRenderingContext2D.prototype.fillText; CanvasRenderingContext2D.prototype.fillText = function (...args) { window.__canvasText.push(String(args[0])); return original.apply(this, args); };
  });
  const requests = []; const consoleErrors = []; page.on("request", (request) => requests.push(request.url())); page.on("console", (message) => { if (message.type() === "error") consoleErrors.push(message.text()); });
  await page.route("**/api/meta", (route) => route.fulfill({ json: { commit: "a".repeat(40) } })); await createIdentity(page);
  const did = await page.locator("#did").textContent(); await mockV2Reply(page, did, { repository: { status: "CONFIRMED" }, commit: { status: "CONFIRMED" }, requested_file: { status: "NOT_CHECKED" } }, { baseline: 0, sequence: 1 });
  await page.locator("#example").click(); page.once("dialog", (dialog) => dialog.accept()); await page.locator("#send").click(); await expect(page.locator("#shareable-receipt")).toBeVisible(); await expect(page.locator("#result-repository")).toHaveText("CONFIRMED"); await expect(page.locator("#result-file")).toHaveText("NOT REQUESTED"); await expect(page.locator("#result-file")).toHaveClass("neutral"); await expect(page.locator("body")).not.toContainText("VERIFIED");
  const digest = await page.locator("#provenance-digest").textContent(); const expectedId = `${digest.slice(0, 4).toUpperCase()}-${digest.slice(4, 8).toUpperCase()}`; await expect(page.locator("#receipt-id")).toHaveText(`Receipt ${expectedId}`);
  await expect(page.locator("#provenance")).not.toHaveAttribute("open"); await page.locator("#provenance summary").click(); await expect(page.locator("#provenance")).toHaveAttribute("open", ""); await expect(page.locator("#result-requester")).toHaveText(did); await expect(page.locator("#result-worker")).toHaveText(WORKER_DID); await expect(page.locator("#provenance-commit")).toHaveText("93dab08e185121186d009f9b637a37365c294ea1"); await expect(page.locator("#provenance-sequence")).toHaveText("1"); await expect(page.locator("#provenance-version")).toHaveText("tc-worker/v2");
  await page.locator("#copy-receipt").click(); const copied = await page.evaluate(() => window.__copied); expect(copied).toBe(`Technocore check\n\npaiin-arc/technocore-beginner-guide\n93dab08e185121186d009f9b637a37365c294ea1\n\nRepository: CONFIRMED\nCommit: CONFIRMED\nFile: NOT REQUESTED\n\nChecked through Technocore\nReceipt: ${expectedId}\n\nWorker: did:key:z6Mkkt…LPNH8djM`); await expect(page.locator("#copy-receipt")).toHaveText("Copied ✓");
  expect(await page.evaluate(() => window.__opened)).toBeNull(); await page.locator("#share-x").click(); const opened = new URL(await page.evaluate(() => window.__opened)); expect(opened.origin).toBe("https://x.com"); expect(opened.pathname).toBe("/intent/post"); expect(opened.searchParams.get("text")).toBe(`Checked a GitHub commit through Technocore.\n\npaiin-arc/technocore-beginner-guide\nRepository ✓\nCommit ✓\n\nReceipt ${expectedId}\n\nhttp://127.0.0.1:18787`);
  const firstDownload = page.waitForEvent("download"); await page.locator("#download-receipt").click(); const png = await (await firstDownload).createReadStream().then(async (stream) => { const parts = []; for await (const part of stream) parts.push(part); return Buffer.concat(parts); }); expect(png.readUInt32BE(16)).toBe(1200); expect(png.readUInt32BE(20)).toBe(675); expect(await page.evaluate(() => window.__canvasText.some((value) => value.startsWith("Requester  did:key:")))).toBe(true);
  await page.evaluate(() => { window.__canvasText = []; }); await page.locator("#include-did-image").uncheck(); const secondDownload = page.waitForEvent("download"); await page.locator("#download-receipt").click(); await secondDownload; expect(await page.evaluate(() => window.__canvasText.includes("Requester DID hidden"))).toBe(true); expect(await page.evaluate(() => window.__canvasText.some((value) => value.startsWith("Requester  did:key:")))).toBe(false);
  const ids = await page.evaluate(async () => { const module = await import("/receipt.js"); return [module.receiptId("a".repeat(64)), module.receiptId("b".repeat(64))]; }); expect(ids).toEqual(["AAAA-AAAA", "BBBB-BBBB"]); expect(consoleErrors).toEqual([]); expect(requests.every((url) => new URL(url).origin === "http://127.0.0.1:18787")).toBe(true); expect(copied).not.toContain(PASSPHRASE); expect(copied).not.toContain("PRIVATE KEY"); expect((await page.evaluate(() => window.__canvasText.join("\n")))).not.toContain(PASSPHRASE);
  await expect(page.locator("#served-commit")).toHaveText("a".repeat(40)); await expect(page.locator(`footer code:has-text("${WORKER_DID}")`)).toBeVisible(); expect(await page.locator('a[href="https://x.com/amjawaeth"]').count()).toBe(1); expect(await page.locator('a[href="https://x.com/flop_labs"]').count()).toBe(1);
});

test("requested file preserves absent and unavailable semantics", async ({ page, browserName }) => {
  test.skip(browserName !== "chromium", "Presentation mapping is browser-independent.");
  const did = await createIdentity(page); const jobs = new Map(); let submission = 0;
  await page.route("**/api/reply-baseline", (route) => route.fulfill({ json: { reply_after: 3 } }));
  await page.route("**/api/technocore/request", async (route) => {
    const body = route.request().postDataJSON(); const request = JSON.parse(body.text); submission += 1;
    jobs.set(request.job, { request, hash: createHash("sha256").update(body.text).digest("hex"), sequence: 20 + submission, status: submission === 3 ? "UNAVAILABLE" : "NOT_FOUND" });
    await route.fulfill({ json: { posted: { seq: 20 + submission, from: did, text: body.text } } });
  });
  await page.route("**/api/jobs/**", (route) => {
    const job = decodeURIComponent(new URL(route.request().url()).pathname.split("/").pop()); const item = jobs.get(job);
    const failed = item.sequence === 21; return route.fulfill({ json: { result: { capability: "contribution-verify", checks: { repository: { status: failed ? "NOT_FOUND" : "CONFIRMED" }, commit: { status: failed ? "NOT_CHECKED" : "CONFIRMED" }, requested_file: { status: failed ? "NOT_CHECKED" : item.status, path: "missing.txt" } }, job, request: { did, room: "mb-technocore-worker", seq: item.sequence, sha256: item.hash, reply_after: 3 }, status: "completed", v: "tc-worker/v2", worker: WORKER_DID } } });
  });
  page.on("dialog", (dialog) => dialog.accept());
  for (const expected of ["FAILED", "NOT_FOUND", "UNAVAILABLE"]) {
    await page.locator("#example").click(); await page.locator("#path").fill("missing.txt"); await page.locator("#send").click();
    if (expected === "FAILED") { await expect(page.locator("#shareable-receipt")).toBeHidden(); await expect(page.locator("#neutral-result")).toBeVisible(); await expect(page.locator("#neutral-repository")).toHaveText("NOT_FOUND"); }
    else { await expect(page.locator("#shareable-receipt")).toBeVisible(); await expect(page.locator("#result-file")).toHaveText(expected); if (expected === "UNAVAILABLE") await expect(page.locator("#result-file")).toHaveClass("secondary"); else await expect(page.locator("#result-file")).not.toHaveClass("secondary"); }
    if (expected !== "UNAVAILABLE") await page.locator("#check-another").click();
  }
});

test("browser timeout does not resubmit the Technocore job", async ({ page, browserName }) => {
  test.skip(browserName !== "chromium", "Protocol timeout behavior is browser-independent.");
  const did = await createIdentity(page); let submissions = 0; let waits = 0;
  await page.route("**/api/reply-baseline", (route) => route.fulfill({ json: { reply_after: 2 } }));
  await page.route("**/api/technocore/request", async (route) => {
    submissions += 1; const body = route.request().postDataJSON();
    await route.fulfill({ json: { posted: { seq: 8, from: did, text: body.text } } });
  });
  await page.route("**/api/jobs/**", (route) => { waits += 1; return route.fulfill({ json: { result: null } }); });
  await page.locator("#example").click(); page.once("dialog", (dialog) => dialog.accept());
  await page.locator("#send").click();
  await expect(page.locator("#status")).toHaveText("Timed out waiting for the worker response.");
  expect(submissions).toBe(1); expect(waits).toBe(36);
  await expect(page.locator("#github-form-wrap")).toBeVisible();
});

test("mobile layout fits and JavaScript-disabled message is useful", async ({ browser }) => {
  const mobileContext = await browser.newContext({ viewport: { width: 390, height: 844 } }); const mobile = await mobileContext.newPage(); const did = await createIdentity(mobile); await mockV2Reply(mobile, did, { repository: { status: "CONFIRMED" }, commit: { status: "CONFIRMED" }, requested_file: { status: "NOT_CHECKED" } }, { baseline: 0, sequence: 1 }); await mobile.locator("#example").click(); mobile.once("dialog", (dialog) => dialog.accept()); await mobile.locator("#send").click(); await expect(mobile.locator("#shareable-receipt")).toBeVisible(); expect(await mobile.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true); await expect(mobile.locator("#receipt-repository")).toBeVisible(); await expect(mobile.locator("#copy-receipt")).toBeVisible(); await mobileContext.close();
  const reduced = await browser.newContext({ reducedMotion: "reduce" }); const reducedPage = await reduced.newPage(); await reducedPage.goto("/"); expect(await reducedPage.locator(".activity i").first().evaluate((node) => getComputedStyle(node).animationName)).toBe("none"); await reduced.close();
  const noJs = await browser.newContext({ javaScriptEnabled: false }); const page = await noJs.newPage(); await page.goto("/"); await expect(page.locator(".noscript")).toContainText("identity creation and signing happen locally"); await noJs.close();
});
