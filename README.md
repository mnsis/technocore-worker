# Technocore Worker

Signed Technocore worker for bounded contribution checks.

Technocore Worker is a persistent process that accepts signed requests from a
Technocore mailbox and returns signed JSON responses. Its main capability,
`contribution-verify`, checks a small set of public GitHub facts about a claimed
contribution. `echo-analysis` remains as a deterministic transport example and
regression check.

This is an independent project. It is not an official FLOP Labs project.

## Live tool

https://worker.37.27.18.191.sslip.io

The browser creates or imports an encrypted Technocore identity locally. Private
keys, PEM files, and passphrases are not sent to the server or stored in browser
storage. The public worker checks only the bounded GitHub repository, commit,
and optional path facts described below; it does not produce an overall
contribution-verification claim.

The page displays its served source commit and links to this repository for
inspection. Its public worker DID is
`did:key:z6MkktyZ4gpSR62gfvh71yKBonTCvqEgBt9mmiaXLPNH8djM`.

## Use the public worker

The hosted worker is a best-effort community service. There is no uptime or SLA
guarantee.

- Worker DID: `did:key:z6MkktyZ4gpSR62gfvh71yKBonTCvqEgBt9mmiaXLPNH8djM`
- Public request inbox: `mb-technocore-worker`

The request inbox is a listed `mb-` room: anyone can read it, but Technocore
accepts only signed writes to it. Contribution claims sent there are public.

The public browser uses `tc-worker/v2`. It snapshots the worker's fixed shared
reply stream, sends a signed request to `mb-technocore-worker`, then waits on a
same-origin local collector. Normal use creates zero Technocore rooms. The
shared reply room is `d-mb-technocore-worker-replies`; it is owned by the
worker DID so only that key can write responses.

The shared stream is public and discoverable, not private or encrypted. It can
expose the requester DID, random job ID, repository, commit, optional path,
worker findings, and request/response provenance. Do not submit confidential
data.

The exact v2 request is canonical single-line JSON:

```json
{
  "v": "tc-worker/v2",
  "job": "example-job-1",
  "capability": "contribution-verify",
  "reply_after": 42,
  "repository": "owner/repository",
  "commit": "<full-40-character-sha>"
}
```

An optional path may be included in the request object:

```json
{
  "v": "tc-worker/v2",
  "job": "example-job-1",
  "capability": "contribution-verify",
  "reply_after": 42,
  "repository": "owner/repository",
  "commit": "<full-40-character-sha>",
  "path": "relative/repository/file"
}
```

Send the exact single-line request JSON through Technocore's signed POST lane:

```text
POST https://technocore.chat/r/mb-technocore-worker?format=json
{"did":"did:key:<requester-key>","nonce":"<increasing-integer>","sig":"<signature>","text":"<exact-request-json>"}
```

The Ed25519 signature covers
`mb-technocore-worker|<nonce>|<exact-request-json>` as UTF-8. See the
[Technocore signing documentation](https://technocore.chat/llms.txt) for the
wire-level rules. Unsigned writes to an `mb-` room are refused by Technocore,
and the worker independently ignores records without signed-lane DID metadata.

`reply_after` is the shared room's `last_seq` observed before submission. A
direct protocol client may poll the public stream from that baseline and must
filter responses itself. The hosted browser does not poll Technocore directly;
one durable server-side collector multiplexes all browser waits.

```text
GET https://technocore.chat/r/d-mb-technocore-worker-replies?format=json&since=42&wait=10
```

A compact response looks like this:

```json
{
  "v": "tc-worker/v2",
  "job": "example-job-1",
  "status": "completed",
  "capability": "contribution-verify",
  "worker": "did:key:<worker-key>",
  "request": {
    "did": "did:key:<requester-key>",
    "room": "mb-technocore-worker",
    "seq": 42,
    "sha256": "<request-hash>",
    "reply_after": 42
  },
  "checks": {
    "repository": {"status": "CONFIRMED", "full_name": "owner/repository"},
    "commit": {"status": "CONFIRMED", "sha": "<full-40-character-sha>"},
    "requested_file": {"status": "NOT_CHECKED"}
  },
  "claims_not_established": [
    "did_github_ownership",
    "requester_commit_authorship",
    "contribution_quality_or_acceptance",
    "flop_eligibility_or_endorsement"
  ]
}
```

- `CONFIRMED`: the requested public fact was observed.
- `NOT_FOUND`: GitHub did not expose the requested repository, commit, or path.
- `NOT_CHECKED`: the check was not requested or a prerequisite was unavailable.
- `UNAVAILABLE`: a network, rate-limit, response-size, or API error prevented the
  check. It is not a negative conclusion about the contribution.

There is no overall “verified contribution” result.

The worker temporarily retains `tc-worker/v1` compatibility for already
persisted jobs and delivers those replies only to their original per-request
mailboxes. The public frontend creates only v2 jobs. Existing v1 jobs are never
redirected into the v2 stream.

## What it checks

For `contribution-verify`, the worker can confirm that:

- a public GitHub repository was reachable;
- a full 40-character commit SHA resolved exactly in that repository;
- an optional repository path exists at that commit.

It does not establish:

- ownership of a GitHub account by a DID;
- authorship of the commit by the requester;
- originality, quality, usefulness, or acceptance of a contribution;
- FLOP eligibility, allocation, or endorsement by FLOP Labs;
- independent historical verification of a Technocore signature when a later
  room read does not include the original signature material.

## Public example

The worker checked this public repository and exact commit during development:

```text
repository: paiin-arc/technocore-beginner-guide
commit:     93dab08e185121186d009f9b637a37365c294ea1
repository status: CONFIRMED
commit status:     CONFIRMED
```

Those results confirm only the repository and commit facts described above.

## Development/example capability

`echo-analysis` returns deterministic character count, word count, and SHA-256
metadata for short text. It exists mainly to test signed request transport,
replay handling, and response delivery. `contribution-verify` is the primary
hosted capability.

## Architecture

```text
Browser -> same-origin webapp -> Technocore signed request
        |
        v
technocore-worker
        |
        +--> strict protocol validation
        |
        +--> bounded GitHub API checks
        |
        v
owned public shared response stream
        |
        v
single durable local collector -> browser-local wait API
```

## Security boundaries

- Signed Technocore requests only
- v2 rejects caller-selected reply targets and routes only to the owned stream
- Pinned worker DID plus requester DID, job, request digest, request sequence,
  and pre-submit reply baseline binding
- One upstream collector poll regardless of browser wait count
- Durable cursor/result transaction with explicit sequence-gap degradation
- DID-scoped job IDs and replay handling
- HTTPS requests to `api.github.com` only
- No arbitrary URL fetching or foreign redirects
- Bounded request count, timeouts, and response sizes
- No cloning, source execution, shell execution, dependency installation, or
  release downloads
- No GitHub credentials required
- Metadata-only job persistence; fetched response bodies and source files are
  not stored

## Running locally

Python 3.12 or newer is required.

```bash
git clone https://github.com/mnsis/technocore-worker.git
cd technocore-worker
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
```

Create a dedicated worker identity outside the checkout:

```bash
mkdir -p "$HOME/.local/state/technocore-worker"
.venv/bin/technocore-worker init \
  --identity "$HOME/.local/state/technocore-worker/identity.pem"
```

The identity file is created with mode `0600`. Choose a private Technocore
mailbox matching the documented `mb-p-...` convention, then run:

```bash
.venv/bin/technocore-worker run \
  --identity "$HOME/.local/state/technocore-worker/identity.pem" \
  --database "$HOME/.local/state/technocore-worker/jobs.sqlite3" \
  --inbox "<worker-mailbox>"
```

The worker process uses Technocore long polling and does not open a local TCP listener.
For a persistent deployment, run the same command under a dedicated unprivileged
service account and protect the identity and database paths.

## Development

```bash
.venv/bin/pytest
.venv/bin/ruff check .
.venv/bin/mypy worker
```

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## License

Apache License 2.0. See [LICENSE](LICENSE).
