# The state file

The connector keeps its device secrets (the vault client's saved state:
its `ik`, `kem` and relay-key seeds, the vault record with tokens and the
session keyring) in one encrypted file per state directory (AGENT-PLAN
§2 AG3, §4.2). The code is `internal/state`; the vectors are
`testdata/vectors/statefile.json` (see `testdata/vectors/SOURCE.md`).

## Files in the state directory

| Name | What |
|---|---|
| `vettid-agent.state` | the state file below |
| `vettid-agent.lock` | the lock file; empty, kept between runs |
| `.vettid-agent.state.<32 hex>.tmp` | a write in progress; one left by a crash is removed by the next process that takes the lock |

## Format, version 1

```
file       = header_len || header || ct_len || ct
header_len : 2 bytes, unsigned big-endian, 1 to 8192
header     : header_len bytes, the canonical JSON header
ct_len     : 4 bytes, unsigned big-endian, 16 to 16 MiB + 16
ct         : ct_len bytes
             = XChaCha20-Poly1305(key   = data key (32 bytes),
                                  nonce = header.nonce (24 bytes),
                                  aad   = header (the exact header bytes),
                                  plaintext = state)
```

Nothing follows `ct`. The header is a JSON object with exactly these
members, in this order, without white space:

```
{"v":1,"protector":"<name>","wrapped_key":"<base64>","nonce":"<base64>","created_at":<seconds>}
```

| Member | Value |
|---|---|
| `v` | `1` |
| `protector` | the protector's name: `[a-z][a-z0-9-]{0,31}` (`passphrase`, and later `tpm`, `keychain`, `dpapi`) |
| `wrapped_key` | the data key as the protector wrapped it, standard base64 with padding, 1 to 4096 bytes before encoding; its inner format is the protector's |
| `nonce` | the AEAD nonce for `ct`, standard base64 with padding, 24 bytes before encoding |
| `created_at` | when the data key was made (the pairing), Unix seconds, positive |

The header must be exactly the bytes Go's `encoding/json` writes for
these values (the canonical form). A reader decodes it, re-encodes it and
compares; any difference (white space, member order, member names in
another case, a duplicate or unknown member, base64 without padding or
with line breaks) is refused. So a header has one encoding, and nothing
in it escapes the authentication through a quirk of a JSON parser.

## Keys and writes

- **Data key**: 32 random bytes, made at `Create` (each pairing) and
  kept by every later `Save`. It is wrapped once by the protector, at
  `Create`; `Save` writes the same `protector`, `wrapped_key` and
  `created_at` with a fresh random `nonce`. A random 192-bit nonce per
  write is safe under one key (VAULT-MESSAGING §4.2 makes the same
  choice for its session AEAD).
- **Atomic write**: a new temporary file in the state directory, created
  exclusively and owner-only, written, synced (`fsync`; `F_FULLFSYNC` on
  macOS through Go's `File.Sync`; `FlushFileBuffers` on Windows), then
  renamed over the state file (`rename`; on Windows `MoveFileEx` with
  `MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH`), then the
  directory synced (POSIX). A crash before the rename leaves the old file
  in place and readable.
- **Owner-only**: on Linux and macOS the directory is mode `0700` and the
  files `0600`, set explicitly after creation so the umask has no effect.
  On Windows the directory and every file are created owned by the
  current user with a protected DACL holding one entry, full access for
  the current user.
- **Lock**: an exclusive, non-blocking lock on `vettid-agent.lock`
  (`flock` on Linux and macOS, `LockFileEx` on Windows), held from
  `Open` to `Close` or process exit. A second process gets "state
  directory is in use by another agent app".

## Reading

A reader refuses, in this order:

1. a state directory that is a symbolic link, not owned by the current
   user, or accessible to anyone else (POSIX: any group or other mode
   bit; Windows: an owner other than the current user, no DACL, an allow
   entry for any other SID, inherit-only entries included, or an entry
   type it does not parse);
2. a state file that is a symbolic link or other reparse point, not a
   regular file, has more than one hard link, or fails the same owner
   and access rules;
3. framing: shorter than its lengths say (`truncated`), longer
   (`trailing bytes`), a length out of range;
4. the header: not JSON, a `v` other than `1` (`unknown version`), not
   canonical, a member missing or out of range;
5. a protector name the build does not know;
6. a wrapped key the protector cannot unwrap, or that does not unwrap
   to 32 bytes;
7. a `ct` that does not authenticate under the data key with the header
   as associated data (a wrong key, or an altered header or body).

Errors name the check that failed, never the data.

## Wipe

`forget` and `device.unlinked` (AGENT-PLAN AG12) overwrite the state
file's bytes with zeros in place, sync it, delete it, delete leftover
temporary files the same way, sync the directory, and call the
protector's `Wipe` to destroy its own key (a TPM object, a Keychain
item). The protector is found from the header's name when the file was
not opened (a forgotten passphrase). Overwriting in place does not
reach copies a journaling or copy-on-write file system or an SSD may
keep; destroying the protector's key does, where the protector has one.

In-memory keys are cleared when no longer needed, as far as Go allows;
copies the runtime made cannot be reached.

## Later versions

A change to this format is a new `v` with its own vectors beside the
version 1 vectors, never an edit of them.
