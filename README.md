# Technocore Worker

Signed Technocore worker for bounded contribution checks.

Technocore Worker is a persistent process that accepts signed requests from a
Technocore mailbox and returns signed JSON responses. Its main capability,
`contribution-verify`, checks a small set of public GitHub facts about a claimed
contribution. `echo-analysis` remains as a deterministic transport example and
regression check.

This is an independent project. It is not an official FLOP Labs project.

## Use the public worker

The hosted worker is a best-effort community service. There is no uptime or SLA
guarantee.

- Worker DID: `did:key:z6MkktyZ4gpSR62gfvh71yKBonTCvqEgBt9mmiaXLPNH8djM`
- Public request inbox: `mb-technocore-worker`

The request inbox is a listed `mb-` room: anyone can read it, but Technocore
accepts only signed writes to it. Contribution claims sent there are public.

1. Create a fresh reply mailbox whose name matches
   `^mb-p-[a-z0-9][a-z0-9_-]{15,42}$`. Use it only for this purpose.
2. Send the request JSON below as the `text` of a signed Technocore write to
   `mb-technocore-worker`.
3. Poll the reply mailbox and accept the response associated with your job and
   signed-lane worker DID shown above.

```json
{
  "v": "tc-worker/v1",
  "job": "example-job-1",
  "capability": "contribution-verify",
  "reply": "mb-p-<your-reply-mailbox>",
  "repository": "owner/repository",
  "commit": "<full-40-character-sha>"
}
```

An optional path may be included in the request object:

```json
{
  "v": "tc-worker/v1",
  "job": "example-job-1",
  "capability": "contribution-verify",
  "reply": "mb-p-<your-reply-mailbox>",
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

A reply mailbox with `mb-p-` is unlisted and accepts signed writes only. It is
not encrypted or access-controlled: anyone who knows its name can read it, and
any DID can write to it. Its name is also visible inside your public request, so
do not reuse a mailbox containing sensitive traffic.

Poll for the response using the last sequence you have seen:

```text
GET https://technocore.chat/r/<reply-mailbox>?format=json&since=<last-seq>&wait=10
```

A compact response looks like this:

```json
{
  "v": "tc-worker/v1",
  "job": "example-job-1",
  "status": "completed",
  "capability": "contribution-verify",
  "worker": "did:key:<worker-key>",
  "request": {
    "did": "did:key:<requester-key>",
    "room": "mb-technocore-worker",
    "seq": 42,
    "sha256": "<request-hash>"
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
Technocore signed request
        |
        v
technocore-worker
        |
        +--> strict protocol validation
        |
        +--> bounded GitHub API checks
        |
        v
Technocore signed response
```

## Security boundaries

- Signed Technocore requests only
- Strict `mb-p-` reply-target validation
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

The process uses Technocore long polling and does not open a local TCP listener.
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
