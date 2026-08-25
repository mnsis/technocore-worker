import { expect, test } from "@playwright/test";
const enabled = process.env.TC_E2E === "1"; const base = process.env.TC_E2E_URL; const pemPath = "/tmp/technocore-phase3c-e2e-identity.pem";
test("one controlled production contribution check", async ({ page, browserName }) => {
  test.skip(!enabled || !base || browserName !== "chromium", "Single explicitly enabled Chromium production run only."); test.setTimeout(180000);
  const passphrase = `phase3c-${crypto.randomUUID()}-local`; const requests = []; const errors = []; page.on("request", (request) => requests.push({ url: request.url(), data: request.postData() || "" })); page.on("console", (message) => { if (message.type() === "error") errors.push(message.text()); });
  await page.goto(base); await page.locator("#new-passphrase").fill(passphrase); await page.locator("#confirm-passphrase").fill(passphrase); await page.locator("#create").click(); await expect(page.locator("#proof-result")).toHaveText("DID control demonstrated"); const did = await page.locator("#did").textContent();
  const downloadPromise = page.waitForEvent("download"); await page.locator("#download").click(); await (await downloadPromise).saveAs(pemPath); await import("node:fs").then(({ chmodSync }) => chmodSync(pemPath, 0o600));
  await page.locator("#example").click(); await page.locator("#send").click(); await expect(page.locator("#status")).toHaveText("Response received", { timeout: 160000 });
  expect(await page.locator("#result-worker").textContent()).toBe("did:key:z6MkktyZ4gpSR62gfvh71yKBonTCvqEgBt9mmiaXLPNH8djM"); expect(await page.locator("#result-repository").textContent()).toBe("CONFIRMED"); expect(await page.locator("#result-commit").textContent()).toBe("CONFIRMED"); expect(errors).toEqual([]);
  for (const request of requests) { expect(new URL(request.url).origin).toBe(new URL(base).origin); expect(request.data).not.toContain(passphrase); expect(request.data).not.toContain("PRIVATE KEY"); }
  const latency = await page.locator("#result-time").textContent(); const worker = await page.locator("#result-worker").textContent();
  await import("node:fs").then(({ writeFileSync }) => writeFileSync("/tmp/technocore-phase3c-e2e-result.json", JSON.stringify({ did, latency, requests: requests.map(({ url }) => url), worker }), { mode: 0o600 }));
});
