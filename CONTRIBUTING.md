# Contributing

Thanks for helping. Claustral is security software, so the bar is: correct first, small second, clever never.

## Setup

- Go 1.27+
- [Task](https://taskfile.dev) (optional; every task is a plain `go` command)

```bash
task check            # gofmt, vet, tests with -race, with and without -tags opentdf
task build            # bin/claustral, local backend only
task build:opentdf    # bin/claustral with the OpenTDF backend
```

## Rules

- **No fake crypto.** No passthrough, "dev" or "mock" encryption modes in non-test code. A backend that cannot encrypt returns an error.
- **Fail closed.** Missing tokens, missing keys, unreadable audit logs and unknown objects deny. Never auto-create a master key on read.
- **Every access is audited.** New operations that reveal plaintext or change access must write an audit event and must not return plaintext if that write fails.
- **Stdlib crypto only** for the local backend (`crypto/aes`, `crypto/cipher`, `crypto/rand`). New dependencies need a reason in the PR.
- **Tests for the unhappy path.** Every change to a backend needs denial, revocation and tamper tests, not just a round trip.
- **Format changes bump the version byte** and keep reading the previous version, or document the break.
- Keep the core package (`pkg/claustral`) free of heavy dependencies. The OpenTDF SDK stays behind the `opentdf` build tag.
- Code is self-explanatory; comments only for a non-obvious "why".

## Adding a backend

Implement `claustral.Backend` in `pkg/<name>`, register it in `internal/app` (behind a build tag if it pulls in large dependencies), and add tests that cover: round trip, denial, revocation or an explicit `ErrUnsupported`, tampered blobs, and wrong-key behavior.

## Reporting security issues

Please do not open a public issue for vulnerabilities. Use GitHub's private vulnerability reporting on the repository.
