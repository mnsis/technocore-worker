const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const ED25519_PREFIX = new Uint8Array([0xed, 0x01]);
const PEM_LABEL = "ENCRYPTED PRIVATE KEY";
const PBKDF2_ITERATIONS = 600000;

const OID = Object.freeze({
  pbes2: "1.2.840.113549.1.5.13",
  pbkdf2: "1.2.840.113549.1.5.12",
  hmacSha256: "1.2.840.113549.2.9",
  aes256Cbc: "2.16.840.1.101.3.4.1.42",
});

const encoder = new TextEncoder();

function concat(...parts) {
  const result = new Uint8Array(parts.reduce((size, part) => size + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

function derLength(length) {
  if (length < 128) return new Uint8Array([length]);
  const bytes = [];
  for (let value = length; value; value >>>= 8) bytes.unshift(value & 255);
  return new Uint8Array([0x80 | bytes.length, ...bytes]);
}

function der(tag, ...contents) {
  const content = concat(...contents);
  return concat(new Uint8Array([tag]), derLength(content.length), content);
}

function derInteger(value) {
  const bytes = [];
  for (let current = value; current; current >>>= 8) bytes.unshift(current & 255);
  if (!bytes.length) bytes.push(0);
  if (bytes[0] & 0x80) bytes.unshift(0);
  return der(0x02, new Uint8Array(bytes));
}

function derOid(value) {
  const numbers = value.split(".").map(Number);
  const body = [numbers[0] * 40 + numbers[1]];
  for (const number of numbers.slice(2)) {
    const encoded = [number & 0x7f];
    for (let current = Math.floor(number / 128); current; current = Math.floor(current / 128)) {
      encoded.unshift(0x80 | (current & 0x7f));
    }
    body.push(...encoded);
  }
  return der(0x06, new Uint8Array(body));
}

function derSequence(...parts) {
  return der(0x30, ...parts);
}

function derOctets(bytes) {
  return der(0x04, bytes);
}

function toBase64(bytes) {
  let binary = "";
  for (let index = 0; index < bytes.length; index += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(index, index + 0x8000));
  }
  return btoa(binary);
}

function fromBase64(value) {
  const binary = atob(value);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

export function base64url(bytes) {
  return toBase64(bytes).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

export function decodeBase64url(value) {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) throw new Error("Malformed base64url value.");
  return fromBase64(value.replaceAll("-", "+").replaceAll("_", "/") + "===".slice((value.length + 3) % 4));
}

function base58(bytes) {
  let number = 0n;
  for (const byte of bytes) number = number * 256n + BigInt(byte);
  let encoded = "";
  while (number) {
    const remainder = Number(number % 58n);
    encoded = B58[remainder] + encoded;
    number /= 58n;
  }
  for (const byte of bytes) {
    if (byte !== 0) break;
    encoded = `1${encoded}`;
  }
  return encoded;
}

export function decodeBase58(value) {
  let number = 0n;
  for (const character of value) {
    const index = B58.indexOf(character);
    if (index < 0) throw new Error("Malformed base58btc value.");
    number = number * 58n + BigInt(index);
  }
  const bytes = [];
  while (number) {
    bytes.unshift(Number(number & 255n));
    number >>= 8n;
  }
  for (const character of value) {
    if (character !== "1") break;
    bytes.unshift(0);
  }
  return new Uint8Array(bytes);
}

export async function didFromPrivateKey(privateKey) {
  const jwk = await crypto.subtle.exportKey("jwk", privateKey);
  const publicBytes = decodeBase64url(jwk.x);
  return `did:key:z${base58(concat(ED25519_PREFIX, publicBytes))}`;
}

export function publicKeyFromDid(did) {
  if (!/^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]{44}$/.test(did)) throw new Error("Malformed Ed25519 DID.");
  const decoded = decodeBase58(did.slice("did:key:z".length));
  if (decoded.length !== 34 || decoded[0] !== 0xed || decoded[1] !== 0x01) {
    throw new Error("DID does not contain a canonical Ed25519 public key.");
  }
  return decoded.slice(2);
}

export async function generateIdentity() {
  if (!crypto?.subtle) throw new Error("WebCrypto is unavailable in this browser.");
  return crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
}

function encryptedPrivateKeyInfo(ciphertext, salt, iv) {
  const pbkdf2Parameters = derSequence(
    derOctets(salt),
    derInteger(PBKDF2_ITERATIONS),
    derSequence(derOid(OID.hmacSha256), der(0x05)),
  );
  const algorithm = derSequence(
    derOid(OID.pbes2),
    derSequence(
      derSequence(derOid(OID.pbkdf2), pbkdf2Parameters),
      derSequence(derOid(OID.aes256Cbc), derOctets(iv)),
    ),
  );
  return derSequence(algorithm, derOctets(ciphertext));
}

export async function exportEncryptedPem(privateKey, passphrase) {
  if (typeof passphrase !== "string" || passphrase.length < 12) {
    throw new Error("Passphrase must contain at least 12 characters.");
  }
  const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", privateKey));
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(16));
  const material = await crypto.subtle.importKey("raw", encoder.encode(passphrase), "PBKDF2", false, ["deriveKey"]);
  const key = await crypto.subtle.deriveKey(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations: PBKDF2_ITERATIONS },
    material,
    { name: "AES-CBC", length: 256 },
    false,
    ["encrypt"],
  );
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-CBC", iv }, key, pkcs8));
  pkcs8.fill(0);
  const encoded = toBase64(encryptedPrivateKeyInfo(ciphertext, salt, iv));
  const lines = encoded.match(/.{1,64}/g).join("\n");
  return `-----BEGIN ${PEM_LABEL}-----\n${lines}\n-----END ${PEM_LABEL}-----\n`;
}

class DerReader {
  constructor(bytes) { this.bytes = bytes; this.offset = 0; }
  item(tag) {
    if (this.bytes[this.offset++] !== tag) throw new Error("Unsupported or malformed encrypted PKCS#8 data.");
    let length = this.bytes[this.offset++];
    if (length & 0x80) {
      const count = length & 0x7f;
      if (!count || count > 4) throw new Error("Malformed DER length.");
      length = 0;
      for (let index = 0; index < count; index += 1) length = length * 256 + this.bytes[this.offset++];
    }
    const end = this.offset + length;
    if (end > this.bytes.length) throw new Error("Truncated DER data.");
    const result = new DerReader(this.bytes.subarray(this.offset, end));
    this.offset = end;
    return result;
  }
  done() { if (this.offset !== this.bytes.length) throw new Error("Unexpected DER data."); }
  raw() { const value = this.bytes.slice(this.offset); this.offset = this.bytes.length; return value; }
  integer() { const bytes = this.item(0x02).raw(); return bytes.reduce((value, byte) => value * 256 + byte, 0); }
  oid() {
    const bytes = this.item(0x06).raw();
    const numbers = [Math.floor(bytes[0] / 40), bytes[0] % 40];
    let current = 0;
    for (const byte of bytes.slice(1)) {
      current = current * 128 + (byte & 0x7f);
      if (!(byte & 0x80)) { numbers.push(current); current = 0; }
    }
    return numbers.join(".");
  }
}

function expectOid(reader, expected) {
  if (reader.oid() !== expected) throw new Error("Unsupported encrypted PKCS#8 algorithm.");
}

function parseEncryptedPrivateKeyInfo(derBytes) {
  const outer = new DerReader(derBytes).item(0x30);
  const algorithm = outer.item(0x30);
  expectOid(algorithm, OID.pbes2);
  const parameters = algorithm.item(0x30);
  const kdf = parameters.item(0x30);
  expectOid(kdf, OID.pbkdf2);
  const pbkdf2 = kdf.item(0x30);
  const salt = pbkdf2.item(0x04).raw();
  const iterations = pbkdf2.integer();
  if (pbkdf2.bytes[pbkdf2.offset] === 0x02) {
    if (pbkdf2.integer() !== 32) throw new Error("Unsupported PBKDF2 key size.");
  }
  const prf = pbkdf2.item(0x30);
  expectOid(prf, OID.hmacSha256);
  prf.item(0x05).done(); prf.done(); pbkdf2.done(); kdf.done();
  const encryption = parameters.item(0x30);
  expectOid(encryption, OID.aes256Cbc);
  const iv = encryption.item(0x04).raw();
  encryption.done(); parameters.done(); algorithm.done();
  const ciphertext = outer.item(0x04).raw();
  outer.done();
  if (salt.length < 8 || iv.length !== 16 || iterations < 1000 || iterations > 10000000) {
    throw new Error("Unsafe or unsupported encrypted PKCS#8 parameters.");
  }
  return { ciphertext, salt, iv, iterations };
}

function pemToDer(pem) {
  if (typeof pem !== "string" || pem.length > 16384) throw new Error("Invalid identity.pem.");
  const match = pem.match(/^-----BEGIN ENCRYPTED PRIVATE KEY-----\r?\n([A-Za-z0-9+/=\r\n]+)-----END ENCRYPTED PRIVATE KEY-----\r?\n?$/);
  if (!match) throw new Error("identity.pem must be an encrypted PKCS#8 PEM.");
  return fromBase64(match[1].replace(/[\r\n]/g, ""));
}

export async function importEncryptedPem(pem, passphrase) {
  if (!passphrase) throw new Error("Passphrase is required.");
  const { ciphertext, salt, iv, iterations } = parseEncryptedPrivateKeyInfo(pemToDer(pem));
  try {
    const material = await crypto.subtle.importKey("raw", encoder.encode(passphrase), "PBKDF2", false, ["deriveKey"]);
    const key = await crypto.subtle.deriveKey(
      { name: "PBKDF2", hash: "SHA-256", salt, iterations }, material,
      { name: "AES-CBC", length: 256 }, false, ["decrypt"],
    );
    const pkcs8 = await crypto.subtle.decrypt({ name: "AES-CBC", iv }, key, ciphertext);
    return await crypto.subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, true, ["sign"]);
  } catch (error) {
    throw new Error("Incorrect passphrase or tampered/unsupported identity.pem.", { cause: error });
  }
}

export async function sign(privateKey, payload) {
  return base64url(new Uint8Array(await crypto.subtle.sign("Ed25519", privateKey, encoder.encode(payload))));
}

export async function verify(did, signature, payload) {
  if (!/^[A-Za-z0-9_-]{86}$/.test(signature)) throw new Error("Malformed Ed25519 signature.");
  const key = await crypto.subtle.importKey("raw", publicKeyFromDid(did), { name: "Ed25519" }, false, ["verify"]);
  return crypto.subtle.verify("Ed25519", key, decodeBase64url(signature), encoder.encode(payload));
}

export const format = Object.freeze({
  type: "PKCS#8 EncryptedPrivateKeyInfo",
  kdf: "PBKDF2-HMAC-SHA256",
  iterations: PBKDF2_ITERATIONS,
  cipher: "AES-256-CBC",
});
