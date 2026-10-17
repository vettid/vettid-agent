# CLAUDE.md

Guidance for Claude Code working in this repository.

## What this is

The VettID agent connector (`vettid-agent`): a Go program that runs next
to an AI agent, pairs with the member's vault as a device of role
`agent` (VAULT-MESSAGING §6.7), acts within access sessions and approvals
(§6.8) under LEASH grants (§10.11), and serves the agent as an **MCP
server over stdio only**: one process started by the MCP client, no
daemon, no local socket or named pipe, no network listener, no service
files.

It is being rebuilt from scratch. The plan, its decisions (§2) and its
phases (§6) are in
[AGENT-PLAN](https://github.com/vettid/vettid.org/blob/master/docs/AGENT-PLAN.md);
read it before starting a PR and do not reopen its decisions. The
2026-05 connector for the retired vettid.dev service is at the tag
`legacy-v1-final` and the branch `legacy/v1`; none of its code is reused.

It needs a staging vault (or vettid-vault's local dev stack): production
release channels do not list the `leash` feature yet.

## Build and test

```sh
go build -o vettid-agent ./cmd/vettid-agent
go vet ./...
go test -p 1 ./...
go test -p 1 -race ./...   # Linux and macOS
```

## Conventions

- Standard library `flag` and `log/slog`; no cobra, zerolog or TOML.
- Pairing, the vault session and LEASH come from
  `github.com/vettid/vettid-vault/client` and `vms/leashwire` at a pinned
  commit (AGENT-PLAN §3.2), recorded in `docs/SOURCE.md`. What the client
  lacks is added in vettid-vault's `client` package, not forked here.
- Package layout per AGENT-PLAN §3.1. Only `internal/vaultconn` touches
  `client.Device`; only `internal/state` and `internal/protect` touch keys
  at rest; `internal/mcp` sees results, never keys.
- Logs carry ids, types, sizes and error codes, never bodies, item
  values, pairing codes or SAS. `vettid-agent mcp` writes only MCP
  messages to standard output; logs go to standard error.

## Coordination rules (AGENT-PLAN §9)

1. **Scope.** Work in `vettid-agent`. Read vettid-vault, vettid-relay,
   vettid-android and vettid.org; never push, comment or open PRs there,
   except issues on vettid.org (rule 4) and vettid-vault PRs of
   AGENT-PLAN §7.1 when the owner assigns them.
2. **Small PRs**, one per row of AGENT-PLAN §6, each with its tests
   passing locally before it is pushed; titles name the row
   (`A2.1: pairing`). The owner merges; the agent never merges.
3. **Public text** (commits, PRs, issues, code comments) never mentions
   reviews, finding ids, private files, local paths outside the
   repository, or device serials. Cite specifications by document and
   section.
4. **Spec questions go to the owner** as a vettid.org issue (title
   starting `AGENT-PLAN:`), never as an edit to a specification. Where
   the spec is silent, choose, mark it "(chosen; not in the spec)" in the
   PR, and ask.
5. **No secrets in the repository**: no keys, tokens, pairing codes,
   state files, passphrases or member data; test keys only from fixed,
   public test seeds; gitleaks runs in CI.
6. **Independent review before merge** for behaviour-changing fixes on
   the lock, unlock, erase and recovery paths: the state store and
   protectors (A1), wiping on `device.unlinked` and `forget`, pairing
   (A2.1) and the save-before-ack rule (A2.2). The owner arranges it;
   such fixes fail secure, retry where safe, and tell the operator
   plainly.
7. **Vectors** (`testdata/vectors/`) are stop-and-report items: never
   edit or skip one that stops matching.
8. **Machine load**: one heavy command at a time; `go test -p 1` for
   integration packages and `-p 2` at most otherwise; one dev stack at a
   time, torn down when done; no parallel test runs from several agents
   on one machine.
9. **Commit trailers and PR bodies**: as the harness provides them; no
   other attribution.
