# Contributing

Keep pull requests focused on one change and include tests for changed behavior.
Before submitting a change, run:

```bash
pytest
ruff check .
mypy worker
```

Preserve the worker's narrow protocol and network boundary. Changes that add
arbitrary URL fetching, repository cloning, source or shell execution, new
outbound hosts, credentials, or broader trust claims need explicit design and
security review; they should not be slipped into routine changes.

Do not commit identities, mailbox capability names, databases, logs, tokens, or
real request data. Use synthetic values in tests.
