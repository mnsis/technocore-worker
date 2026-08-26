import { didFromPrivateKey, exportEncryptedPem, generateIdentity, importEncryptedPem, sign } from "./crypto.js";
import { WORKER_DID, WORKER_INBOX, canonicalContributionRequest, freshJobId, freshNonce, parseWorkerReply, signedWrite } from "./protocol.js";

let privateKey = null; let did = null; let downloaded = false; let controlProved = false; let pollAbort = null; let pemBlobUrl = null; let elapsedTimer = null;
const byId = (id) => document.getElementById(id);
const status = (message, kind = "") => { byId("status").textContent = message; byId("status").dataset.kind = kind; };
const fieldRules = {
  repository: { valid: (value) => /^[A-Za-z0-9-]+\/[A-Za-z0-9_.-]+$/.test(value) },
  commit: { valid: (value) => /^[0-9a-fA-F]{40}$/.test(value) },
  path: { valid: (value) => !value || /^[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)*$/.test(value) },
};
const touchedFields = new Set();

function setProgress(current, completed = []) {
  for (const item of document.querySelectorAll(".flow li")) {
    item.className = completed.includes(item.dataset.stage) ? "completed" : item.dataset.stage === current ? "current" : "";
  }
}
function selectIdentityPanel(name) {
  const create = name === "create"; byId("create-panel").hidden = !create; byId("import-panel").hidden = create;
  for (const [id, active] of [["show-create", create], ["show-import", !create]]) { byId(id).classList.toggle("active", active); byId(id).setAttribute("aria-selected", String(active)); }
}
byId("show-create").addEventListener("click", () => selectIdentityPanel("create")); byId("show-import").addEventListener("click", () => selectIdentityPanel("import"));

function validateContribution(showAll = false) {
  let valid = Boolean(privateKey && controlProved);
  for (const [name, rule] of Object.entries(fieldRules)) {
    const input = byId(name); const fieldValid = rule.valid(input.value.trim()); valid &&= fieldValid;
    const showError = !fieldValid && (showAll || touchedFields.has(name)); input.setAttribute("aria-invalid", String(showError)); byId(`${name}-error`).hidden = !showError;
  }
  byId("send").disabled = !valid; return valid;
}
for (const name of Object.keys(fieldRules)) {
  byId(name).setAttribute("aria-describedby", `${name}-error`);
  byId(name).addEventListener("input", () => { touchedFields.add(name); validateContribution(); });
  byId(name).addEventListener("blur", () => { touchedFields.add(name); validateContribution(); });
}
function revokePemBlobUrl() { if (!pemBlobUrl) return; URL.revokeObjectURL(pemBlobUrl); pemBlobUrl = null; byId("download").removeAttribute("href"); }
function stopElapsed() { if (elapsedTimer !== null) clearInterval(elapsedTimer); elapsedTimer = null; }
function startElapsed(started) { stopElapsed(); const update = () => { byId("waiting-elapsed").textContent = `${((performance.now() - started) / 1000).toFixed(1)}s`; }; update(); elapsedTimer = setInterval(update, 100); }

async function demonstrateControl() {
  byId("control-stage").hidden = false; byId("control-stage").classList.remove("completed"); byId("proof-result").textContent = "Signing local challenge…"; setProgress("control", ["identity"]);
  try {
    const challengeResponse = await fetch("/api/challenge", { headers: { Accept: "application/json" }, cache: "no-store" });
    if (!challengeResponse.ok) throw new Error("Could not obtain a same-origin challenge."); const challenge = await challengeResponse.json(); const signature = await sign(privateKey, challenge.payload);
    const result = await fetch("/api/challenge/verify", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ did, challenge: challenge.challenge, signature }) });
    if (!result.ok) throw new Error((await result.json()).error || "DID control proof failed.");
    controlProved = true; byId("control-stage").classList.add("completed"); byId("proof-result").textContent = "DID control demonstrated"; byId("github-stage").hidden = false; byId("contribution-fields").disabled = false; validateContribution(); setProgress("github", ["identity", "control"]); status("DID control demonstrated", "ok");
  } catch (error) { byId("control-stage").hidden = true; byId("identity-setup").hidden = false; byId("identity-ready").hidden = true; status(error.message, "error"); }
}
function showIdentity() {
  controlProved = false; byId("did").textContent = did; byId("identity-setup").hidden = true; byId("identity-ready").hidden = false; byId("backup-note").hidden = downloaded;
  touchedFields.clear(); status("Identity ready", "ok"); void demonstrateControl();
}
byId("create").addEventListener("click", async () => {
  try {
    const passphrase = byId("new-passphrase").value; if (passphrase.length < 12) throw new Error("Use a passphrase of at least 12 characters."); if (passphrase !== byId("confirm-passphrase").value) throw new Error("Passphrases do not match.");
    privateKey = (await generateIdentity()).privateKey; did = await didFromPrivateKey(privateKey); const pem = await exportEncryptedPem(privateKey, passphrase); revokePemBlobUrl(); pemBlobUrl = URL.createObjectURL(new Blob([pem], { type: "application/x-pem-file" }));
    byId("download").href = pemBlobUrl; byId("download").hidden = false; downloaded = false; byId("new-passphrase").value = ""; byId("confirm-passphrase").value = ""; showIdentity();
  } catch (error) { status(error.message, "error"); }
});
byId("download").addEventListener("click", () => { downloaded = true; byId("backup-note").hidden = false; byId("backup-note").textContent = "✓ Encrypted backup downloaded"; byId("download").hidden = true; status("Encrypted identity.pem downloaded", "ok"); setTimeout(revokePemBlobUrl, 0); });
byId("import").addEventListener("click", async () => {
  try { const file = byId("pem-file").files[0]; if (!file || file.size > 16384) throw new Error("Choose a valid identity.pem file."); privateKey = await importEncryptedPem(await file.text(), byId("import-passphrase").value); did = await didFromPrivateKey(privateKey); downloaded = true; byId("import-passphrase").value = ""; byId("download").hidden = true; showIdentity(); } catch (error) { status(error.message, "error"); }
});

function resetGithub() {
  pollAbort?.abort(); stopElapsed(); document.body.classList.remove("job-active"); document.querySelector(".workspace").classList.remove("job-active"); byId("download").textContent = "Download identity.pem"; byId("result-stage").hidden = true; byId("checking").hidden = true; byId("github-stage").hidden = false; byId("github-form-wrap").hidden = false; byId("repository").value = ""; byId("commit").value = ""; byId("path").value = ""; touchedFields.clear();
  for (const item of byId("execution").children) item.className = ""; validateContribution(); setProgress("github", ["identity", "control"]); status("Ready for another check", "ok");
}
byId("use-another").addEventListener("click", () => {
  privateKey = null; did = null; downloaded = false; controlProved = false; pollAbort?.abort(); revokePemBlobUrl(); byId("identity-ready").hidden = true; byId("identity-setup").hidden = false; byId("control-stage").hidden = true; byId("github-stage").hidden = true; byId("result-stage").hidden = true; byId("pem-file").value = ""; resetGithub(); byId("github-stage").hidden = true; setProgress("identity"); status("Create or import an identity to begin.");
});
byId("check-another").addEventListener("click", resetGithub);
byId("example").addEventListener("click", () => { byId("repository").value = "paiin-arc/technocore-beginner-guide"; byId("commit").value = "93dab08e185121186d009f9b637a37365c294ea1"; byId("path").value = ""; touchedFields.clear(); validateContribution(); });

async function sha256(text) { const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text))); return Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join(""); }
function execution(step) { const order = ["signed", "sent", "waiting"]; const current = order.indexOf(step); for (const item of byId("execution").children) { const index = order.indexOf(item.dataset.step); item.className = index < current ? "done" : index === current ? "active" : ""; } }
async function pollReply(expected) {
  pollAbort = new AbortController();
  for (let attempt = 0; attempt < 36; attempt += 1) { const url = `/api/jobs/${encodeURIComponent(expected.job)}?did=${encodeURIComponent(expected.did)}&sha256=${expected.sha256}&n=${attempt}`; const response = await fetch(url, { headers: { Accept: "application/json" }, cache: "no-store", signal: pollAbort.signal }); if (response.status === 503) throw new Error("Worker reply service is temporarily unavailable."); if (!response.ok) throw new Error("Could not read the worker result."); const body = await response.json(); const parsed = parseWorkerReply(body, expected); if (parsed) return parsed; }
  throw new Error("Timed out waiting for the worker response.");
}
function resultState(value) { return value === "CONFIRMED" ? "confirmed" : value === "UNAVAILABLE" ? "secondary" : value === "NOT REQUESTED" ? "neutral" : ""; }
function showResult(result, elapsed, requestedPath) {
  stopElapsed();
  const values = { repository: result.checks?.repository?.status, commit: result.checks?.commit?.status, file: requestedPath ? result.checks?.requested_file?.status : "NOT REQUESTED" };
  for (const [name, value] of Object.entries(values)) { const target = byId(`result-${name}`); target.textContent = value || "UNAVAILABLE"; target.className = resultState(target.textContent); }
  const duration = `${(elapsed / 1000).toFixed(1)}s`; byId("result-time").textContent = duration; byId("result-time-row").textContent = duration; byId("result-worker").textContent = result.worker; byId("result-requester").textContent = result.request.did;
  byId("github-stage").hidden = true; byId("result-stage").hidden = false; setProgress("result", ["identity", "control", "github"]); status("Response received", "ok");
}
byId("contribution").addEventListener("submit", async (event) => {
  event.preventDefault(); try {
    if (!validateContribution(true)) return; const repository = byId("repository").value.trim(); const commit = byId("commit").value.trim(); const path = byId("path").value.trim();
    if (!downloaded && !confirm("You have not downloaded identity.pem. Continue without a recoverable encrypted copy?")) return;
    byId("github-form-wrap").hidden = true; byId("checking").hidden = false; byId("checking-repository").textContent = repository; byId("checking-commit").textContent = commit; const started = performance.now(); document.body.classList.add("job-active"); document.querySelector(".workspace").classList.add("job-active"); byId("download").textContent = "Download backup"; setProgress("result", ["identity", "control", "github"]); startElapsed(started); status("Preparing signed request");
    const baselineResponse = await fetch("/api/reply-baseline", { headers: { Accept: "application/json" }, cache: "no-store" }); if (!baselineResponse.ok) throw new Error("Worker reply service is temporarily unavailable."); const baseline = await baselineResponse.json(); const replyAfter = baseline.reply_after;
    const job = freshJobId(); const nonce = freshNonce(); const text = canonicalContributionRequest({ job, repository, commit, path: path || undefined, replyAfter }); const body = await signedWrite(privateKey, did, WORKER_INBOX, nonce, text); execution("sent");
    const response = await fetch("/api/technocore/request", { method: "POST", headers: { Accept: "application/json", "Content-Type": "application/json" }, body: JSON.stringify(body) }); if (!response.ok) throw new Error("Technocore rejected the signed request."); const posted = await response.json(); if (!Number.isInteger(posted.posted?.seq) || posted.posted?.from !== did || posted.posted?.text !== text) throw new Error("Technocore returned a mismatched write receipt."); execution("waiting"); status("Waiting for worker");
    const result = await pollReply({ job, did, sha256: await sha256(text), sequence: posted.posted.seq, replyAfter }); if (result.worker !== WORKER_DID || result.request.did !== did) throw new Error("Worker response identity mismatch."); for (const item of byId("execution").children) item.className = "done"; byId("execution").querySelector('[data-step="waiting"] span:nth-of-type(2)').textContent = "Worker replied"; showResult(result, performance.now() - started, path);
  } catch (error) { stopElapsed(); document.body.classList.remove("job-active"); document.querySelector(".workspace").classList.remove("job-active"); byId("checking").hidden = true; byId("github-form-wrap").hidden = false; setProgress("github", ["identity", "control"]); status(error.name === "AbortError" ? "Polling stopped." : error.message, "error"); }
  finally { validateContribution(); pollAbort = null; }
});

fetch("/api/meta", { headers: { Accept: "application/json" }, cache: "no-store" }).then((response) => response.ok ? response.json() : Promise.reject()).then((meta) => { byId("served-commit").textContent = meta.commit; }).catch(() => { byId("served-commit").textContent = "unavailable"; });
window.addEventListener("pagehide", () => { privateKey = null; did = null; pollAbort?.abort(); stopElapsed(); revokePemBlobUrl(); });
