# Contributing to the VettID agent connector

Thank you for your interest. The connector is being rebuilt to the plan
in [AGENT-PLAN](https://github.com/vettid/vettid.org/blob/master/docs/AGENT-PLAN.md);
changes should fit one of its phases.

## Getting started

1. Fork the repository and clone your fork.
2. Create a branch.
3. Make your change, with tests.
4. Run `gofmt -l .`, `go vet ./...` and `go test ./...` (and
   `go test -race ./...` where cgo is available).
5. Open a pull request.

## Requirements

- Go at the version in `go.mod` or later.

## Code style

- Standard Go conventions (`gofmt`, `go vet`); the standard library
  where it suffices.
- Keep functions focused and small; write tests for new behaviour.
- Specification references cite the document and section, for example
  "VAULT-MESSAGING §6.7".

## Security

**Never commit** keys, tokens, pairing codes, state files, passphrases,
personal data or any other secret. Test keys come only from fixed,
public test seeds.

If you discover a security vulnerability, report it privately. Do
**not** open a public issue.

## License

By contributing, you agree that your contributions are licensed under
AGPL-3.0.
