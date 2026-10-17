# Vectors copied from vettid-vault

The vault's vectors are authoritative (VAULT-MESSAGING §16). These are
byte-for-byte copies from vettid-vault at the commit pinned in `go.mod`
(see `docs/SOURCE.md`), checked here against the vault packages the
connector is built with (AGENT-PLAN §5).

**A vector that stops matching is a stop-and-report item: never edit a
file here or skip a case.** Re-copy all of them from the new commit when
the pin changes, and update this file in the same PR.

Source commit: vettid-vault `1ef2dd9ec68627a80e18d665032fcd58e3a61a1d`
(2026-10-17).

| File | Source path | sha256sum | Checked by |
|---|---|---|---|
| `leash.json` | `testdata/vectors/leash.json` | `b1200366e5310cd5ac7bbded3bb035b6efa1408579a7c19bd4a73ca9fcba2beb` | `vectors_test.go` `TestLeashVectors` |

`TestLeashVectors` checks the file's sha256 against this table, that each
key matches its seed, and for each case (`a`, `b`) that
`leashwire.VerifyPresented` under the credential key accepts the
delegation with its status statement at `accept_from`, `accept_to` and
between them, and refuses it one second outside that window, under the
agent's or the vault's key instead of the member's, without a status
statement, with any of the four parts altered by one bit (first, middle
and last byte), with the two signatures swapped, and with the other
case's status statement.

`.gitattributes` keeps line endings unchanged on every platform, so the
sha256 holds on Windows checkouts too.
