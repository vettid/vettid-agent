# Vectors copied from vettid-vault

The vault's vectors are authoritative (VAULT-MESSAGING §16). These are
byte-for-byte copies from vettid-vault at the commit pinned in `go.mod`
(see `docs/SOURCE.md`), checked here against the vault packages the
connector is built with (AGENT-PLAN §5).

**A vector that stops matching is a stop-and-report item: never edit a
file here or skip a case.** Re-copy all of them from the new commit when
the pin changes, and update this file in the same PR.

Source commit: vettid-vault `f75ea0b945b7a665a1edf676c1b70e67ac42ff75`
(2026-10-18). The files copied here are byte-identical at the earlier
pins `271f3e23c0331d5fcd33c3bcb6fb2fc579a4911d` and
`1ef2dd9ec68627a80e18d665032fcd58e3a61a1d`; the sha256 values below are
unchanged.

| File | Source path | sha256sum | Checked by |
|---|---|---|---|
| `leash.json` | `testdata/vectors/leash.json` | `b1200366e5310cd5ac7bbded3bb035b6efa1408579a7c19bd4a73ca9fcba2beb` | `vectors_test.go` `TestLeashVectors` |
| `invite.json` | `testdata/vectors/invite.json` | `6d7be9ba65f8426070ee54f0ea6ed84fed1e49c54eb31e09a1e177d3d5286d2f` | `internal/pairing` `TestInviteVector` |
| `handshake.json` | `testdata/vectors/handshake.json` | `9b69503b507fd117ab3d6a66368cb60bb24e09286867921a6f473fb476fb0577` | `internal/pairing` `TestHandshakeVector` |

`TestLeashVectors` checks the file's sha256 against this table, that each
key matches its seed, and for each case (`a`, `b`) that
`leashwire.VerifyPresented` under the credential key accepts the
delegation with its status statement at `accept_from`, `accept_to` and
between them, and refuses it one second outside that window, under the
agent's or the vault's key instead of the member's, without a status
statement, with any of the four parts altered by one bit (first, middle
and last byte), with the two signatures swapped, and with the other
case's status statement.

`TestInviteVector` checks the file's sha256, that `link` decodes to
`qr_json`, that the code forms of §6.4 (the bare payload, the URL form on
the vector's relay and on another host, `vettid://connect#`, inside
surrounding text, the same code twice) all find the payload with the
payload's `r` as the relay, that this connection code (`t` = "c") is
refused as not an agent code, that the same QR as an agent code passes
until one second before `e` and is refused from `e` on, that the blob
opens against `h` and round-trips to `bundle_json`, that the blob
altered by one bit (first, middle and last byte) is refused by the hash
check, and that an agent QR over this connection bundle is refused for
its kind. Two different codes, truncated or altered payloads and text
without a code are refused.

`TestHandshakeVector` checks the file's sha256 and, from the
initiator's side through the imported handshake package: `hs.resp`
opens under the ephemeral key (seed 32 x 0x0c) and gives `K_e` and
`n_R`; the transcript hashes `th1` and `th`; with the vector's `K_s`,
the key schedule gives `prk`; `hs.fin` opens with `k_i2r` and reveals
`n_I`, which opens `sas_commit`; and the SAS is the vector's `564218`,
shown as `564 218`.

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
| `passphrase.json` | (generated here) | `4e2d87c90e35bebd7f6f22ddc7a8c51acbca35d1fa1a69a225744bda355e5984` | `internal/protect` `TestPassphraseVectors` |

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
`internal/state`. Its passphrase holds a non-ASCII letter; the NFC case
gives the same text in decomposed form (different bytes), which must
normalize to the passphrase and wrap to the same blob. `TestPassphraseVectors` regenerates it and compares it
byte for byte, checks this table's sha256, unwraps the blob, and loads
the state file through `internal/state` (not on Windows; see the test).
The production derivation runs once per test run. To regenerate:

```sh
go test ./internal/protect -run TestPassphraseVectors -update
```
