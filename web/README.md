# Browser identity frontend

The public frontend is the static site in this directory, hosted on Vercel at
`https://technocore-worker.vercel.app`. Vercel serves the assets and rewrites
`/api/*` to the VPS origin server `https://worker.37.27.18.191.sslip.io/api/*`
(see `vercel.json`). The VPS runs TLS-terminating Nginx in front of the
loopback-only Python application, which still holds the worker, the reply
collector, and Technocore access. The browser only ever talks to its own
Vercel origin.

The Python application accepts exactly one browser `Origin`
(`https://technocore-worker.vercel.app`, used for Host/Origin/session/challenge
validation) and exactly one `Host` header (`worker.37.27.18.191.sslip.io`, the
value a Vercel external rewrite presents). These are configured with
`--public-origin` and `--request-host`; wildcards are not used.

## Cryptographic compatibility

- Ed25519 keys come from WebCrypto and are exported as PKCS#8
  `EncryptedPrivateKeyInfo` PEM (`BEGIN ENCRYPTED PRIVATE KEY`).
- Encryption uses standard PBES2 with PBKDF2-HMAC-SHA256 (600,000 iterations, 16-byte
  salt) and AES-256-CBC with a random 16-byte IV. Python `cryptography` loads this
  stronger browser profile. Browser import also accepts Python `BestAvailableEncryption`,
  whose current OpenSSL-generated PBES2 profile uses a lower fixed iteration count.
  Unencrypted and non-PBES2 PEM are rejected.
- The DID is `did:key:` plus multibase base58btc (`z`) of the Ed25519 public-key
  multicodec prefix `0xed01` followed by the raw 32-byte public key.
- Message normalization replaces Unicode categories Cc, Cf, Cs, Co, Zl, and Zp with
  ASCII space, then strips leading/trailing whitespace. The signed UTF-8 bytes are
  `<room>|<nonce>|<normalized-text>`. Signatures are unpadded base64url Ed25519.

The private key is extractable because encrypted PKCS#8 export is a requirement. It
stays in JavaScript memory and is not written to browser storage. Reloading or closing
the page loses it. The downloaded encrypted PEM is the only persistence mechanism.

## Network boundary

The browser connects only to the same-origin frontend. Its two Technocore proxy
routes are fixed-purpose: one accepts only the four public signed-write fields and only
a valid `contribution-verify` request; the other reads only a syntactically valid private
reply mailbox. The challenge verifier accepts only DID, challenge, and signature. No
route accepts PEM, passphrase, seed phrase, or private-key fields.

## Browser support and trust

Current Chromium, Firefox, and Safari versions with WebCrypto Ed25519, PBKDF2-SHA256,
and AES-CBC are targeted. There is no fallback when a primitive is unavailable.

This is not absolute non-leakage. The current served JavaScript handles the key locally.
An XSS bug, compromised frontend origin, malicious dependency, malicious browser
extension, or future compromised server response could steal it. The prototype has no
runtime dependencies, uses no HTML injection sinks, logs no secrets, applies a strict
CSP, disables browser persistence, discourages autofill, and avoids clipboard features.
Those controls do not protect against a browser extension or an origin that serves
malicious JavaScript. Passphrases remain JavaScript strings until garbage-collected;
JavaScript cannot reliably zero them. Downloaded PEMs inherit the browser and operating
system's file handling and permissions.

Challenge proofs are random, expire after two minutes, are consumed on the first verify
attempt, and bind purpose, local origin, random session identifier, challenge, and expiry.
Success means only: “Control of this DID was demonstrated for this session.”

Challenges and rate-limit counters are held in bounded process memory. Restarting the
web process invalidates all outstanding challenges, so a pre-restart challenge cannot be
replayed afterward. Limits per direct client IP per minute are 20 challenge creations,
20 verification attempts, five Technocore forwards, and 120 reply polls. Forwarded-IP
headers are deliberately ignored.

The production frontend and proxy run together behind a dedicated Nginx virtual host
with request and connection limits, HSTS, and no mutable third-party assets. The page
retrieves its served source commit from the same-origin `/api/meta` endpoint and displays
it in the footer.
