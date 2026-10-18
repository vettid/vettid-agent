# Pinned sources

The connector builds on vettid-vault's reference client and wire packages
instead of reimplementing the protocol (AGENT-PLAN §2 AG2, §3.2). They
are pinned to one commit; a change to the pin is its own PR, with the
vectors of `testdata/vectors/` re-copied from the new commit and their
tests passing (AGENT-PLAN §5, §10 risk 2).

| Module | Version in `go.mod` | Commit | Date (UTC) |
|---|---|---|---|
| `github.com/vettid/vettid-vault` | `v0.0.0-20261018030705-f75ea0b945b7` | `f75ea0b945b7a665a1edf676c1b70e67ac42ff75` (`main`, "client: Paired, device.paired's fields kept in the state", #113) | 2026-10-18 03:07:05 |
| `github.com/vettid/vettid-relay` (the version vettid-vault requires; imported directly since A2.1) | `v0.0.0-20261015153542-cc3ce892f9dc` | `cc3ce892f9dcb990e9e9752f19c3e0e296dd12b9` (`main`, RELAY-PROTOCOL 0.9.4 byte budgets, #14) | 2026-10-15 15:35:42 |

Other direct dependencies are ordinary tagged releases chosen in the PR
that adds them: `golang.org/x/crypto`, `x/sys`, `x/term`, `x/text`, and
for the Linux TPM protector `github.com/google/go-tpm` v0.9.8 (Apache-2.0,
compatible with AGPL-3.0; pure Go). `github.com/google/go-tpm-tools`
v0.4.11 (Apache-2.0) is used only by tests, for its TPM 2.0 simulator
(the Microsoft reference implementation, built with cgo on the Linux CI
job); it is not linked into the binary.

## Why these commits

- **vettid-vault `271f3e2`** (A2.2) adds to the A0.2 pin `1ef2dd9` the
  client's `Config.Persist` (AGENT-PLAN §7.1 AV1: the device state is
  saved after a collected batch is handled and before it is
  acknowledged, with the deposits that handling makes kept in a saved
  outbox, and `device.paired` recorded while it is handled), the wallet
  calls moved to `client/wallet` (AV4), and the vault's bound on
  access-session prompts (AV6). The vault's vectors used here are
  unchanged between the two commits (same sha256). The module has no
  tags, so the dependency is a pseudo-version of a `main` commit.
- **vettid-vault `f75ea0b`** (A2 follow-ups) adds `(*Device).Paired()`:
  `device.paired`'s fields kept in the client state, among them the end
  of the first access session (`SessionExpiresAt`), which pairing now
  records. The vectors used here are unchanged (same sha256).
- **vettid-relay `cc3ce89`** is not chosen here: it is the version
  vettid-vault `f75ea0b` requires in its own `go.mod` (the relay client
  and token packages its `client` imports), and Go's minimal version
  selection keeps it. It is recorded so that a relay change reaching the
  connector is visible in review.

## What is used

- `github.com/vettid/vettid-vault/client`: pairing, the vault session,
  tokens and LEASH (AGENT-PLAN §3.2).
- `github.com/vettid/vettid-vault/vms/leashwire`: the reference verifier
  of delegations and status statements (VAULT-MESSAGING §10.11).
- `github.com/vettid/vettid-vault/vms/invite`, `vms/handshake`,
  `vms/envelope` and `vms/suite`: the pairing code's checks and the
  `invite.json` and `handshake.json` vectors (A2.1); the tests' simulated
  vault builds its messages with them.
- `github.com/vettid/vettid-relay/relayclient` and `relayauth` (a direct
  dependency since A2.1, at the version vettid-vault requires): a relay
  error's status, and the tests' simulated relay.

Both are outside the vault module's `internal/`; their own imports of
`internal/strictjson`, `internal/cbor` and `internal/der` are allowed
because those packages are inside the vault module. Since AV4 the wallet
calls are in `client/wallet`, which the connector does not import, so
btcsuite/btcd and decred secp256k1 are no longer compiled in.

## Checks

- `go mod verify` (CI, every platform).
- `deps_test.go`: imports `client` and `vms/leashwire` and uses one
  exported function of each.
- `vectors_test.go`: the vault's `leash.json` vectors against
  `leashwire.VerifyPresented`; see `testdata/vectors/SOURCE.md`.
