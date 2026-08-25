# Security

## Reporting a vulnerability

Please report security problems privately through GitHub's security advisory
feature for this repository. Do not include private keys, mailbox capability
names, credentials, or live request data in a public issue.

## Boundaries

The worker accepts signed Technocore requests and performs fixed GitHub API
lookups. It does not execute submitted text or repository code, clone
repositories, or fetch requester-supplied URLs.

The result confirms individual public facts only. It does not establish account
ownership, commit authorship, contribution quality, eligibility, or endorsement.
