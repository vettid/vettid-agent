# Contributing to VettID Agent Connector

Thank you for your interest in contributing to VettID Agent Connector.

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/<you>/vettid-agent.git`
3. Create a branch: `git checkout -b my-feature`
4. Make your changes
5. Run tests: `make test`
6. Run linter: `make lint`
7. Commit and push
8. Open a Pull Request

## Development Requirements

- Go 1.24+
- GNU Make

## Code Style

- Follow standard Go conventions (`gofmt`, `go vet`)
- Mark security-critical sections with `// SECURITY:` comments
- Keep functions focused and small
- Write tests for new functionality

## Security

**Never commit:**
- Encryption keys or credentials
- Connection tokens or NATS credentials
- Platform key files
- Any PII or secrets

If you discover a security vulnerability, please report it privately. Do **not** open a public issue.

## License

By contributing, you agree that your contributions will be licensed under AGPL-3.0.
