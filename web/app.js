import { didFromPrivateKey, exportEncryptedPem, generateIdentity, importEncryptedPem, sign } from "./crypto.js";
import { WORKER_INBOX, canonicalContributionRequest, freshJobId, freshNonce, freshReplyMailbox, parseWorkerReply, signedWrite } from "./protocol.js";

let privateKey = null;
let did = null;
let downloaded = false;
let pollAbort = null;
let pemBlobUrl = null;
const byId = (id) => document.getElementById(id);
const status = (message, kind = "") => { byId("status").textContent = message; byId("status").dataset.kind = kind; };

function revokePemBlobUrl() {
  if (!pemBlobUrl) return;
  URL.revokeObjectURL(pemBlobUrl);
  pemBlobUrl = null;
  byId("download").removeAttribute("href");
}

function showIdentity() {
  byId("did").textContent = did;
  byId("identity-ready").hidden = false;
  byId("contribution-fields").disabled = false;
  status("Identity ready", "ok");
}

byId("create").addEventListener("click", async () => {
  try {
    const passphrase = byId("new-passphrase").value;
    if (passphrase !== byId("confirm-passphrase").value) throw new Error("Passphrases do not match.");
    privateKey = (await generateIdentity()).privateKey;
    did = await didFromPrivateKey(privateKey);
    const pem = await exportEncryptedPem(privateKey, passphrase);
    revokePemBlobUrl();
    pemBlobUrl = URL.createObjectURL(new Blob([pem], { type: "application/x-pem-file" }));
    byId("download").href = pemBlobUrl;
    byId("download").hidden = false;
    downloaded = false;
    byId("new-passphrase").value = ""; byId("confirm-passphrase").value = "";
    showIdentity();
  } catch (error) { status(error.message, "error"); }
});

byId("download").addEventListener("click", () => {
  downloaded = true;
  status("Identity ready — encrypted identity.pem downloaded", "ok");
  setTimeout(revokePemBlobUrl, 0);
});

byId("import").addEventListener("click", async () => {
  try {
    const file = byId("pem-file").files[0];
    if (!file || file.size > 16384) throw new Error("Choose a valid identity.pem file.");
    privateKey = await importEncryptedPem(await file.text(), byId("import-passphrase").value);
    did = await didFromPrivateKey(privateKey);
    downloaded = true;
    byId("import-passphrase").value = "";
    showIdentity();
  } catch (error) { status(error.message, "error"); }
});

byId("prove").addEventListener("click", async () => {
  try {
    if (!privateKey) throw new Error("Create or import an identity first.");
    const challengeResponse = await fetch("/api/challenge", { headers: { Accept: "application/json" }, cache: "no-store" });
    if (!challengeResponse.ok) throw new Error("Could not obtain a local challenge.");
    const challenge = await challengeResponse.json();
    const signature = await sign(privateKey, challenge.payload);
    const result = await fetch("/api/challenge/verify", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ did, challenge: challenge.challenge, signature }),
    });
    if (!result.ok) throw new Error((await result.json()).error || "Challenge proof failed.");
    byId("proof-result").textContent = "Control of this DID was demonstrated for this session.";
  } catch (error) { status(error.message, "error"); }
});

async function sha256(text) {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)));
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function pollReply(reply, expected) {
  pollAbort = new AbortController();
  let cursor = 0;
  for (let attempt = 0; attempt < 36; attempt += 1) {
    status("Worker processing");
    const url = `/api/technocore/reply?room=${encodeURIComponent(reply)}&since=${cursor}&n=${attempt}`;
    const response = await fetch(url, { headers: { Accept: "application/json" }, cache: "no-store", signal: pollAbort.signal });
    if (!response.ok) throw new Error("Could not read the reply mailbox.");
    const room = await response.json();
    if (room.room !== reply || !Array.isArray(room.messages)) throw new Error("Malformed reply mailbox response.");
    for (const record of room.messages) {
      const parsed = parseWorkerReply(record, expected);
      if (parsed) return parsed;
    }
    if (Number.isInteger(room.last_seq)) cursor = Math.max(cursor, room.last_seq);
  }
  throw new Error("Timed out waiting for the worker response.");
}

byId("contribution").addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    if (!privateKey) throw new Error("Create or import an identity first.");
    if (!downloaded && !confirm("You have not downloaded identity.pem. Continue without a recoverable encrypted copy?")) return;
    byId("send").disabled = true;
    const job = freshJobId(); const reply = freshReplyMailbox(); const nonce = freshNonce();
    const text = canonicalContributionRequest({
      job, reply, repository: byId("repository").value.trim(),
      commit: byId("commit").value.trim(), path: byId("path").value.trim() || undefined,
    });
    const body = await signedWrite(privateKey, did, WORKER_INBOX, nonce, text);
    status("Request signed", "ok");
    const response = await fetch("/api/technocore/request", {
      method: "POST", headers: { "Accept": "application/json", "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!response.ok) throw new Error("Technocore rejected the signed request.");
    const posted = await response.json();
    const sequence = posted.posted?.seq;
    if (!Number.isInteger(sequence) || posted.posted?.from !== did || posted.posted?.text !== text) throw new Error("Technocore returned a mismatched write receipt.");
    status("Sent to Technocore", "ok");
    const result = await pollReply(reply, { job, did, sha256: await sha256(text) });
    byId("result").textContent = JSON.stringify(result, null, 2);
    status("Result received", "ok");
  } catch (error) { status(error.name === "AbortError" ? "Polling stopped." : error.message, "error"); }
  finally { byId("send").disabled = false; pollAbort = null; }
});

window.addEventListener("pagehide", () => {
  privateKey = null; did = null; pollAbort?.abort(); revokePemBlobUrl();
});
