import { sign, verify } from "./crypto.js";

export const WORKER_INBOX = "mb-technocore-worker";
export const WORKER_DID = "did:key:z6MkktyZ4gpSR62gfvh71yKBonTCvqEgBt9mmiaXLPNH8djM";
const ROOM = /^[a-z0-9][a-z0-9_-]{0,47}$/;
const REPOSITORY = /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?\/[A-Za-z0-9_.-]{1,100}$/;
const SHA = /^[0-9a-fA-F]{40}$/;
const PATH = /^[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)*$/;

export function normalizeMessage(text) {
  const normalized = text.replace(/[\p{Cc}\p{Cf}\p{Cs}\p{Co}\p{Zl}\p{Zp}]/gu, " ").trim();
  if (!normalized || normalized.length > 4096) throw new Error("Message is empty or too long after normalization.");
  return normalized;
}

export function messagePayload(room, nonce, text) {
  if (!ROOM.test(room)) throw new Error("Invalid Technocore room.");
  const nonceText = String(nonce);
  if (!/^[0-9]{1,19}$/.test(nonceText)) throw new Error("Invalid Technocore nonce.");
  const normalized = normalizeMessage(text);
  return { normalized, payload: `${room}|${nonceText}|${normalized}` };
}

function randomToken(length) {
  const bytes = crypto.getRandomValues(new Uint8Array(length));
  return Array.from(bytes, (byte) => "abcdefghijklmnopqrstuvwxyz0123456789"[byte % 36]).join("");
}

export function freshReplyMailbox() { return `mb-p-${randomToken(24)}`; }
export function freshJobId() { return `browser-${randomToken(20)}`; }
export function freshNonce() {
  const bytes = crypto.getRandomValues(new Uint8Array(8));
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return String(value % 10000000000000000000n);
}

export function canonicalContributionRequest({ job, reply, repository, commit, path }) {
  if (!/^[a-z0-9][a-z0-9_-]{0,63}$/.test(job)) throw new Error("Invalid job ID.");
  if (!/^mb-p-[a-z0-9][a-z0-9_-]{15,42}$/.test(reply)) throw new Error("Invalid reply mailbox.");
  if (!REPOSITORY.test(repository) || repository.endsWith(".") || repository.split("/")[1].includes("..")) throw new Error("Use owner/repository, not a URL.");
  if (!SHA.test(commit)) throw new Error("Commit must be a full 40-character SHA.");
  if (path && (!PATH.test(path) || path.length > 240 || path.split("/").some((part) => part === "." || part === ".."))) throw new Error("Invalid repository path.");
  const value = { capability: "contribution-verify", commit: commit.toLowerCase(), job, reply, repository, v: "tc-worker/v1" };
  if (path) value.path = path;
  return JSON.stringify(value, Object.keys(value).sort());
}

export async function signedWrite(privateKey, did, room, nonce, text) {
  const { normalized, payload } = messagePayload(room, nonce, text);
  return { did, nonce: String(nonce), sig: await sign(privateKey, payload), text: normalized };
}

export function parseWorkerReply(record, expected) {
  if (!record || record.from !== WORKER_DID || typeof record.text !== "string") return null;
  let response;
  try { response = JSON.parse(record.text); } catch { return null; }
  if (response.v !== "tc-worker/v1" || response.capability !== "contribution-verify" ||
      response.status !== "completed" || response.worker !== WORKER_DID || response.job !== expected.job ||
      response.request?.did !== expected.did || response.request?.room !== WORKER_INBOX ||
      response.request?.sha256 !== expected.sha256) return null;
  return response;
}

export async function verifyWorkerDidSignature(signature, payload) {
  return verify(WORKER_DID, signature, payload);
}
