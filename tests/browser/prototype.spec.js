import { createHash } from "node:crypto";
import { expect, test } from "@playwright/test";

const PASSPHRASE = "headless compatibility passphrase";
const WORKER_DID = "did:key:z6MkktyZ4gpSR62gfvh71yKBonTCvqEgBt9mmiaXLPNH8djM";

async function createIdentity(page) {
  await page.goto("/");
  await page.locator("#new-passphrase").fill(PASSPHRASE);
  await page.locator("#confirm-passphrase").fill(PASSPHRASE);
  await page.locator("#create").click();
  await expect(page.locator("#status")).toHaveText("Identity ready");
  return page.locator("#did").textContent();
}

test("creates, downloads, proves control, and loses memory state on reload", async ({ page }) => {
  await page.addInitScript(() => {
    const original = URL.revokeObjectURL.bind(URL);
    window.__revokedPemUrls = [];
    URL.revokeObjectURL = (value) => { window.__revokedPemUrls.push(value); original(value); };
  });
  const requests = [];
  page.on("request", (request) => requests.push({ url: request.url(), data: request.postData() }));
  const response = await page.goto("/");
  expect(response.headers()["content-security-policy"]).toContain("connect-src 'self'");
  expect(response.headers()["content-security-policy"]).not.toContain("'unsafe-inline'");
  const did = await createIdentity(page);
  expect(did).toMatch(/^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]{44}$/);
  const downloadPromise = page.waitForEvent("download");
  await page.locator("#download").click();
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toBe("identity.pem");
  const downloadPath = await download.path();
  const pem = await import("node:fs").then(({ readFileSync }) => readFileSync(downloadPath, "utf8"));
  expect(pem).toMatch(/^-----BEGIN ENCRYPTED PRIVATE KEY-----/);
  expect(pem).not.toContain("BEGIN PRIVATE KEY");
  await expect.poll(() => page.evaluate(() => window.__revokedPemUrls.length)).toBe(1);
  await expect(page.locator("#download")).not.toHaveAttribute("href");
  await page.locator("#prove").click();
  await expect(page.locator("#proof-result")).toHaveText("Control of this DID was demonstrated for this session.");
  for (const request of requests) {
    expect(request.url).toMatch(/^http:\/\/127\.0\.0\.1:18787\//);
    expect(request.data || "").not.toContain(PASSPHRASE);
    expect(request.data || "").not.toContain("PRIVATE KEY");
  }
  await page.reload();
  await expect(page.locator("#identity-ready")).toBeHidden();
  await expect(page.locator("#send")).toBeDisabled();
});

test("imports locally and completes a mocked unchanged worker exchange", async ({ page }) => {
  await createIdentity(page);
  const downloadPromise = page.waitForEvent("download");
  await page.locator("#download").click();
  const pemPath = await (await downloadPromise).path();
  await page.reload();
  await page.locator("#pem-file").setInputFiles(pemPath);
  await page.locator("#import-passphrase").fill(PASSPHRASE);
  await page.locator("#import").click();
  await expect(page.locator("#status")).toHaveText("Identity ready");
  const did = await page.locator("#did").textContent();

  let expected;
  await page.route("**/api/technocore/request", async (route) => {
    const body = route.request().postDataJSON();
    expect(Object.keys(body).sort()).toEqual(["did", "nonce", "sig", "text"]);
    expect(JSON.stringify(body)).not.toContain(PASSPHRASE);
    const request = JSON.parse(body.text);
    expected = { request, hash: createHash("sha256").update(body.text).digest("hex") };
    await route.fulfill({ json: { posted: { seq: 7, from: did, text: body.text } } });
  });
  await page.route("**/api/technocore/reply?*", async (route) => {
    const response = {
      capability: "contribution-verify", checks: {}, job: expected.request.job,
      request: { did, room: "mb-technocore-worker", sha256: expected.hash },
      status: "completed", v: "tc-worker/v1", worker: WORKER_DID,
    };
    await route.fulfill({ json: { room: expected.request.reply, last_seq: 1, messages: [{ from: WORKER_DID, text: JSON.stringify(response) }] } });
  });
  await page.locator("#repository").fill("paiin-arc/technocore-beginner-guide");
  await page.locator("#commit").fill("93dab08e185121186d009f9b637a37365c294ea1");
  await page.locator("#send").click();
  await expect(page.locator("#status")).toHaveText("Result received");
  await expect(page.locator("#result")).toContainText(WORKER_DID);
});
