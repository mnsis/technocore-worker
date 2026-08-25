import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { webcrypto } from "node:crypto";
import {
  didFromPrivateKey, exportEncryptedPem, generateIdentity, importEncryptedPem, sign, verify,
} from "../web/crypto.js";
import {
  WORKER_DID, WORKER_INBOX, canonicalContributionRequest, messagePayload, parseWorkerReply,
  signedWrite,
} from "../web/protocol.js";

globalThis.crypto = webcrypto;

const directory = process.argv[2];
const python = JSON.parse(fs.readFileSync(path.join(directory, "python.json"), "utf8"));
const pythonPem = fs.readFileSync(path.join(directory, "python.pem"), "utf8");
const imported = await importEncryptedPem(pythonPem, python.passphrase);
assert.equal(await didFromPrivateKey(imported), python.did);
assert.equal(await verify(python.did, python.signature, python.payload), true);
assert.equal(await sign(imported, python.payload).then((value) => verify(python.did, value, python.payload)), true);
await assert.rejects(() => importEncryptedPem(pythonPem, "wrong-passphrase"), /Incorrect passphrase/);
const tampered = pythonPem.replace(/[A-Za-z0-9]/, (character) => character === "A" ? "B" : "A");
await assert.rejects(() => importEncryptedPem(tampered, python.passphrase));
await assert.rejects(() => verify("did:key:bad", python.signature, python.payload), /Malformed/);
await assert.rejects(() => verify(python.did, "bad", python.payload), /Malformed/);

const generated = await generateIdentity();
const browserDid = await didFromPrivateKey(generated.privateKey);
const browserPem = await exportEncryptedPem(generated.privateKey, python.passphrase);
const browserSignature = await sign(generated.privateKey, python.payload);
fs.writeFileSync(path.join(directory, "browser.pem"), browserPem, { mode: 0o600 });
fs.writeFileSync(path.join(directory, "browser.json"), JSON.stringify({ did: browserDid, signature: browserSignature }));

const reply = "mb-p-0123456789abcdef01234567";
const job = "browser-test";
const request = canonicalContributionRequest({
  job, reply, repository: "paiin-arc/technocore-beginner-guide",
  commit: "93dab08e185121186d009f9b637a37365c294ea1",
});
assert.equal(request, '{"capability":"contribution-verify","commit":"93dab08e185121186d009f9b637a37365c294ea1","job":"browser-test","reply":"mb-p-0123456789abcdef01234567","repository":"paiin-arc/technocore-beginner-guide","v":"tc-worker/v1"}');
assert.throws(() => canonicalContributionRequest({ job, reply, repository: "https://github.com/a/b", commit: "a".repeat(40) }));
const body = await signedWrite(generated.privateKey, browserDid, WORKER_INBOX, "123", request);
assert.deepEqual(messagePayload(WORKER_INBOX, "123", request).payload, `${WORKER_INBOX}|123|${request}`);
assert.equal(await verify(browserDid, body.sig, `${WORKER_INBOX}|123|${request}`), true);

const expected = { job, did: browserDid, sha256: "a".repeat(64) };
const response = {
  capability: "contribution-verify", job, status: "completed", v: "tc-worker/v1", worker: WORKER_DID,
  request: { did: browserDid, room: WORKER_INBOX, sha256: "a".repeat(64) }, checks: {},
};
assert.deepEqual(parseWorkerReply({ from: WORKER_DID, text: JSON.stringify(response) }, expected), response);
assert.equal(parseWorkerReply({ from: python.did, text: JSON.stringify(response) }, expected), null);
assert.equal(parseWorkerReply({ from: WORKER_DID, text: "not-json" }, expected), null);
