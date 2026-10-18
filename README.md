# VettID agent connector

`vettid-agent` is a small program that runs next to an AI agent and gives
it a narrow, audited way to use what a VettID member has delegated to it.
It pairs with the member's vault as a device of role `agent`
(VAULT-MESSAGING §6.7), acts only within access sessions and approvals
the member grants on their phone (§6.8), and reaches the member's items
under LEASH grants (§10.11). The vault, not the connector, enforces the
grants, limits and approvals.

The agent talks to it as an **MCP server over standard input and
output**: the MCP client (an IDE assistant or an agent framework) starts
`vettid-agent mcp` itself, and the process exits when the client closes
it. There is no daemon, no local socket and no network listener; the
only network traffic goes to the vault's relay.

## Status: being rebuilt

The 2026-05 connector, written for the retired vettid.dev service, has
been removed. Its last state is kept at the tag `legacy-v1-final` and on
the branch `legacy/v1`; its old releases do not work with the current
vault.

The rebuild follows the agent connector plan,
[AGENT-PLAN](https://github.com/vettid/vettid.org/blob/master/docs/AGENT-PLAN.md),
in small phases. Today the binary has only `version`; `pair`, `mcp`,
`status` and `forget` are listed as not yet available.

**It needs a staging vault.** Only vaults whose release channel lists the
optional `leash` feature answer agent pairing. Staging images list it;
production does not yet, so no production vault can pair a connector
until a production release lists `leash`. Until the phone app can pair
agents, development runs against vettid-vault's local dev stack.

## Build and test

Go at the version in `go.mod` or later.

```sh
go build -o vettid-agent ./cmd/vettid-agent
./vettid-agent version

go vet ./...
go test ./...
go test -race ./...    # where cgo is available (Linux, macOS)
```

CI runs `go vet`, `go test` (with `-race` on Linux and macOS), gitleaks
and govulncheck on Linux, macOS and Windows runners.

## Design rules

- Item values pass through to the agent and are never written to disk or
  logs; nothing caches a secret beyond the one tool result.
- One connector, one vault: each MCP client gets its own state directory
  and its own pairing, which the member can remove separately.
- Keys at rest are wrapped by a platform protector (TPM 2.0, macOS
  Keychain, Windows DPAPI) or, where none exists, a passphrase. The
  state file's format, owner-only rules and lock are in
  [docs/STATE-FILE.md](docs/STATE-FILE.md).

## Keys at rest on Linux: the TPM

On Linux the connector seals its state file's key to the computer's TPM
2.0 through the kernel's resource manager, `/dev/tpmrm0`, so that a copy
of the state file does not open on another computer. The user that runs
the connector needs access to that device (on most distributions,
membership of the `tss` group). Without a TPM, or without access to it,
the connector says what is wrong and how to fix it (for example, add
your user to the `tss` group), and uses a passphrase only if you ask for
one; on a computer with no TPM at all it uses a passphrase and says so.
The sealed key is not bound to PCR measurements, so firmware and kernel
updates do not lock the connector out.

The sealed key lives only inside the state file. `forget` overwrites and
deletes that file, but an old copy recovered from the disk afterwards (a
backup, a file system snapshot, a block an SSD remapped) can still be
opened on this computer until its TPM is cleared. Opening such a copy
needs the copy (from a backup, a snapshot or the raw disk) and access to
this computer's TPM.

## Passphrase (computers without a platform protector)

Where no TPM, Keychain or DPAPI protector is available, the keys are
protected by a passphrase only: at least 12 characters, using at least 3
of lower-case letters, upper-case letters, digits, and symbols,
punctuation or letters without case (such as Chinese or Japanese
characters); spaces count for no class. It is not bound to the computer: the state file and the
passphrase open it anywhere.

The connector takes the passphrase from one of:

- a prompt on the terminal (no echo), when neither flag is given;
- `--passphrase-file PATH`: a regular file holding the passphrase on one
  line (one trailing line break is ignored). It must be private to you:
  on Linux and macOS owned by you and readable by you only (`chmod 600`);
  on Windows owned by you with no access for anyone else (for example
  `icacls <file> /inheritance:r /grant:r "%USERNAME%:F"`);
- `--passphrase-fd N`: a pipe or regular file the parent process opened
  as descriptor `N`, read up to the first line break. A regular file
  must be private to you, as for `--passphrase-file`. A pipe can be an
  anonymous pipe (preferred) or a named FIFO on disk. Every pipe must
  belong to you, and a FIFO must be mode `0600` (readable and writable by
  you only), or the connector refuses it. Descriptors 0, 1 and 2 are refused, so
  `echo … | vettid-agent … --passphrase-fd 0` is not supported; use
  another descriptor, for example a pipe from a secret store,
  `vettid-agent … --passphrase-fd 3 3< <(secret-tool lookup …)`, or a
  file made with `chmod 600`, `vettid-agent … --passphrase-fd 3
  3< passphrase.txt`, or `--passphrase-file`. On Windows `N` is an
  inherited handle value, not a C runtime descriptor.

The passphrase is read **before** the state directory is opened; a
descriptor given while the connector already holds its state directory
is refused.

## License

AGPL-3.0; see [LICENSE](LICENSE). Contributions: see
[CONTRIBUTING.md](CONTRIBUTING.md).
