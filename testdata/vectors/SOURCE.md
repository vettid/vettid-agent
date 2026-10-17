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

## The connector's own vectors

Not copied from anywhere: generated in this repository from fixed,
public test inputs (AGENT-PLAN §5). The same rule applies: a vector that
stops matching is a stop-and-report item. A change to the state file
format is a new header version with new vectors beside these, never an
edit of these.

| File | Source path | sha256sum | Checked by |
|---|---|---|---|
| `statefile.json` | (generated here) | `36fd3d093bc43e41e6dae56833cb42f5fe05a41969467582f1f5359ba640ef6f` | `internal/state` `TestStateFileVectors` |
| `passphrase.json` | (generated here) | `0bed121bea0a7b3e640c119a6db4c49f387acf43331ce30e1c02c55106e9182f` | `internal/protect` `TestPassphraseVectors` |

`statefile.json` holds the state file format of `docs/STATE-FILE.md`
under a test-only protector with a fixed key (`test-fixed`), a fixed data
key, nonce and `created_at`: one valid file, and files refused for a
tampered header (each still canonical JSON, so that only the
authentication catches it), a non-canonical header (white space, member
case, a duplicate or unknown member, member order), an unknown version,
an unknown protector, a wrapped key under another protector key, a header
wrapping another data key, five truncations, a trailing byte and a
tampered tag. Each case names its expected result (`ok`,
`format: <check>`, `unknown_protector`, `unwrap` or `decrypt`).

`TestStateFileVectors` regenerates the file and compares it byte for
byte, checks this table's sha256, and decodes every case. To regenerate
after a deliberate change (a new version, reviewed as such):

```sh
go test ./internal/state -run TestStateFileVectors -update
```

`passphrase.json` is the passphrase protector at its production
Argon2id parameters (t = 3, m = 64 MiB, p = 1): a fixed passphrase, salt,
wrapping nonce, data key and state nonce; the Argon2id output, the
wrapped data key, and a whole state file built independently of
`internal/state`. `TestPassphraseVectors` regenerates it and compares it
byte for byte, checks this table's sha256, unwraps the blob, and loads
the state file through `internal/state` (not on Windows; see the test).
The production derivation runs once per test run. To regenerate:

```sh
go test ./internal/protect -run TestPassphraseVectors -update
```
