import { didFromPrivateKey, exportEncryptedPem, generateIdentity, importEncryptedPem, sign } from "./crypto.js";
import { WORKER_DID, WORKER_INBOX, canonicalContributionRequest, freshJobId, freshNonce, freshReplyMailbox, parseWorkerReply, signedWrite } from "./protocol.js";

let privateKey = null; let did = null; let downloaded = false; let controlProved = false; let pollAbort = null; let pemBlobUrl = null;
const byId = (id) => document.getElementById(id);
const status = (message, kind = "") => { byId("status").textContent = message; byId("status").dataset.kind = kind; };
byId("contribution").noValidate = true;

function selectIdentityPanel(name) {
  const create = name === "create";
  byId("create-panel").hidden = !create; byId("import-panel").hidden = create;
  for (const [id, active] of [["show-create", create], ["show-import", !create]]) {
    byId(id).classList.toggle("active", active); byId(id).setAttribute("aria-selected", String(active));
  }
}
byId("show-create").addEventListener("click", () => selectIdentityPanel("create"));
byId("show-import").addEventListener("click", () => selectIdentityPanel("import"));

function revokePemBlobUrl() { if (!pemBlobUrl) return; URL.revokeObjectURL(pemBlobUrl); pemBlobUrl = null; byId("download").removeAttribute("href"); }
function showIdentity() {
  controlProved = false; byId("did").textContent = did; byId("identity-ready").hidden = false;
  byId("prove").disabled = false; byId("proof-result").textContent = "Ready to demonstrate control.";
  byId("contribution-fields").disabled = true; byId("send").disabled = true; status("Identity ready", "ok");
}

byId("create").addEventListener("click", async () => {
  try {
    const passphrase = byId("new-passphrase").value;
    if (passphrase.length < 12) throw new Error("Use a passphrase of at least 12 characters.");
    if (passphrase !== byId("confirm-passphrase").value) throw new Error("Passphrases do not match.");
    privateKey = (await generateIdentity()).privateKey; did = await didFromPrivateKey(privateKey);
    const pem = await exportEncryptedPem(privateKey, passphrase); revokePemBlobUrl();
    pemBlobUrl = URL.createObjectURL(new Blob([pem], { type: "application/x-pem-file" }));
    byId("download").href = pemBlobUrl; byId("download").hidden = false; downloaded = false;
    byId("new-passphrase").value = ""; byId("confirm-passphrase").value = ""; showIdentity();
  } catch (error) { status(error.message, "error"); }
});
byId("download").addEventListener("click", () => { downloaded = true; status("Encrypted identity.pem downloaded", "ok"); setTimeout(revokePemBlobUrl, 0); });
byId("import").addEventListener("click", async () => {
  try {
    const file = byId("pem-file").files[0]; if (!file || file.size > 16384) throw new Error("Choose a valid identity.pem file.");
    privateKey = await importEncryptedPem(await file.text(), byId("import-passphrase").value); did = await didFromPrivateKey(privateKey);
    downloaded = true; byId("import-passphrase").value = ""; byId("download").hidden = true; showIdentity();
  } catch (error) { status(error.message, "error"); }
});

byId("prove").addEventListener("click", async () => {
  try {
    if (!privateKey) throw new Error("Create or import an identity first."); byId("prove").disabled = true; byId("proof-result").textContent = "Signing challenge…";
    const challengeResponse = await fetch("/api/challenge", { headers: { Accept: "application/json" }, cache: "no-store" });
    if (!challengeResponse.ok) throw new Error("Could not obtain a same-origin challenge.");
    const challenge = await challengeResponse.json(); const signature = await sign(privateKey, challenge.payload);
    const result = await fetch("/api/challenge/verify", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ did, challenge: challenge.challenge, signature }) });
    if (!result.ok) throw new Error((await result.json()).error || "DID control proof failed.");
    controlProved = true; byId("proof-result").textContent = "DID control demonstrated"; byId("contribution-fields").disabled = false; byId("send").disabled = false; status("DID control demonstrated", "ok");
  } catch (error) { byId("prove").disabled = false; status(error.message, "error"); }
});

byId("example").addEventListener("click", () => { byId("repository").value = "paiin-arc/technocore-beginner-guide"; byId("commit").value = "93dab08e185121186d009f9b637a37365c294ea1"; byId("path").value = ""; });
async function sha256(text) { const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text))); return Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join(""); }
function progress(step) { const order = ["prepare", "sent", "waiting", "received"]; const current = order.indexOf(step); for (const item of byId("progress").children) { const index = order.indexOf(item.dataset.step); item.className = index < current ? "done" : index === current ? "active" : ""; } }
async function pollReply(reply, expected) {
  pollAbort = new AbortController(); let cursor = 0;
  for (let attempt = 0; attempt < 36; attempt += 1) {
    const url = `/api/technocore/reply?room=${encodeURIComponent(reply)}&since=${cursor}&n=${attempt}`;
    const response = await fetch(url, { headers: { Accept: "application/json" }, cache: "no-store", signal: pollAbort.signal });
    if (!response.ok) throw new Error("Could not read the reply mailbox."); const room = await response.json();
    if (room.room !== reply || !Array.isArray(room.messages)) throw new Error("Malformed reply mailbox response.");
    for (const record of room.messages) { const parsed = parseWorkerReply(record, expected); if (parsed) return parsed; }
    if (Number.isInteger(room.last_seq)) cursor = Math.max(cursor, room.last_seq);
  } throw new Error("Timed out waiting for the worker response.");
}
function resultState(value) { return value === "CONFIRMED" ? "confirmed" : value === "NOT_CHECKED" || value === "UNAVAILABLE" ? "secondary" : ""; }
function showResult(result, elapsed) {
  const values = { repository: result.checks?.repository?.status, commit: result.checks?.commit?.status, file: result.checks?.requested_file?.status };
  for (const [name, value] of Object.entries(values)) { const target = byId(`result-${name}`); target.textContent = value || "UNAVAILABLE"; target.className = resultState(target.textContent); }
  byId("result-time").textContent = `${(elapsed / 1000).toFixed(1)}s`; byId("result-worker").textContent = result.worker; byId("result-requester").textContent = result.request.did; byId("result-card").hidden = false;
}
byId("contribution").addEventListener("submit", async (event) => {
  event.preventDefault(); try {
    if (!privateKey || !controlProved) throw new Error("Demonstrate DID control first.");
    const repository = byId("repository").value.trim(); const commit = byId("commit").value.trim(); const path = byId("path").value.trim();
    if (!/^[A-Za-z0-9-]+\/[A-Za-z0-9_.-]+$/.test(repository)) throw new Error("Repository must use owner/repository format.");
    if (!/^[0-9a-fA-F]{40}$/.test(commit)) throw new Error("Commit must be a full 40-character SHA.");
    if (path && !/^[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)*$/.test(path)) throw new Error("Optional file must be a relative path.");
    if (!downloaded && !confirm("You have not downloaded identity.pem. Continue without a recoverable encrypted copy?")) return;
    byId("send").disabled = true; byId("result-card").hidden = true; const started = performance.now(); progress("prepare"); status("Preparing signed request");
    const job = freshJobId(); const reply = freshReplyMailbox(); const nonce = freshNonce();
    const text = canonicalContributionRequest({ job, reply, repository, commit, path: path || undefined });
    const body = await signedWrite(privateKey, did, WORKER_INBOX, nonce, text);
    const response = await fetch("/api/technocore/request", { method: "POST", headers: { Accept: "application/json", "Content-Type": "application/json" }, body: JSON.stringify(body) });
    if (!response.ok) throw new Error("Technocore rejected the signed request."); const posted = await response.json();
    if (!Number.isInteger(posted.posted?.seq) || posted.posted?.from !== did || posted.posted?.text !== text) throw new Error("Technocore returned a mismatched write receipt.");
    progress("sent"); status("Sent to Technocore", "ok"); await new Promise((resolve) => setTimeout(resolve, 150)); progress("waiting"); status("Waiting for worker");
    const result = await pollReply(reply, { job, did, sha256: await sha256(text) });
    if (result.worker !== WORKER_DID || result.request.did !== did) throw new Error("Worker response identity mismatch.");
    progress("received"); showResult(result, performance.now() - started); status("Response received", "ok");
  } catch (error) { status(error.name === "AbortError" ? "Polling stopped." : error.message, "error"); }
  finally { byId("send").disabled = !controlProved; pollAbort = null; }
});

fetch("/api/meta", { headers: { Accept: "application/json" }, cache: "no-store" }).then((response) => response.ok ? response.json() : Promise.reject()).then((meta) => { byId("served-commit").textContent = meta.commit; }).catch(() => { byId("served-commit").textContent = "unavailable"; });
window.addEventListener("pagehide", () => { privateKey = null; did = null; pollAbort?.abort(); revokePemBlobUrl(); });
