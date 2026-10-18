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
| `.vettid-agent.state.<32 hex>.tmp` | a write in progress; one left by a crash is overwritten and removed by the next process that takes the lock |

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
| `protector` | the protector's name: `[a-z][a-z0-9-]{0,31}` (`passphrase`, `tpm`, `dpapi`, and later `keychain`) |
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
  macOS through Go's `File.Sync`; `FlushFileBuffers` on Windows), renamed
  over the state file, and the directory synced; `Create`, `Save` and
  `CreateReplace` return only after all of that. If a flush after the
  rename fails, the error says that the new file is in place but may not
  be durable. A crash before the
  rename leaves the old file in place and readable.
  - POSIX: `rename`, then `fsync` of the directory.
  - Windows: a rename with POSIX semantics (`FileRenameInfoEx` with
    `FILE_RENAME_REPLACE_IF_EXISTS | FILE_RENAME_POSIX_SEMANTICS`), which
    works while the old file is held open, falling back to `MoveFileEx`
    with `MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH` where the
    file system lacks it; then `FlushFileBuffers` on the renamed file and
    on the directory (opened with `FILE_FLAG_BACKUP_SEMANTICS`). Where a
    file system refuses to flush a directory, what remains is its own
    behaviour: NTFS journaling keeps the directory consistent after a
    crash (the old entry or the new one), but that alone does not make
    the new entry durable.
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

## The `dpapi` wrapped key (Windows)

The DPAPI protector's `wrapped_key` (internal/protect/dpapi_blob.go):

```
wrapped_key = version (1 byte, 0x01) || dpapi
dpapi       = CryptProtectData(plaintext,
                               description = "vettid-agent data key",
                               entropy     = "vettid-agent/protect/dpapi/v1\x00",
                               flags       = CRYPTPROTECT_UI_FORBIDDEN)
              in user scope (never CRYPTPROTECT_LOCAL_MACHINE), unchanged
plaintext   = data key (32 bytes)
              || SHA-256("vettid-agent/protect/dpapi/v1 check\x00" || data key)[:16]
```

Nothing follows `dpapi`. Before calling Windows, a reader refuses any
other version byte and checks the DPAPI blob's layout (all little
endian): blob version 1, the DPAPI provider GUID
`{df9d8cd0-1501-11d1-8c7a-00c04fc297eb}`, master key version 1, the
flags exactly 0 (what Windows writes for a user-scope blob made with
`CRYPTPROTECT_UI_FORBIDDEN`; so a machine-scope blob, flag
`CRYPTPROTECT_LOCAL_MACHINE`, is refused), the description above
(UTF-16 with its terminating NUL), AES-128, -192 or -256 with SHA-256,
-384 or -512, each length-prefixed field non-empty (the HMAC key may be
empty) and at most 1024 bytes, and nothing left over. Microsoft does not
document this layout; `Wrap` checks its own output against the same
rules. After Windows decrypts, the description it returns and the check
value must match, else the key is refused (Microsoft documents that
CryptUnprotectData may succeed with corrupted output). The entropy is a
public constant: it keeps these blobs apart from other programs' DPAPI
blobs, and any process running as the same user can open them.

## Wipe

`forget` and `device.unlinked` (AGENT-PLAN AG12) wipe in this order:

1. The protector's key first (`Protector.Wipe`: a Keychain item;
   nothing for the passphrase, TPM and DPAPI protectors, whose wrapped
   key lives only in the file). The protector
   is the one that created or opened the file or, when the file was not
   opened (a forgotten passphrase), the one named in the header. If its
   wipe fails, the state file is kept and the error returned, so that a
   retry finds the protector again.
2. The state file's bytes are overwritten with zeros in place, synced,
   and the file deleted; leftover temporary files the same way; the
   directory synced. A symbolic link at either path is deleted itself,
   never followed.

If the protector cannot be determined (an unreadable or zeroed header,
or no file and nothing opened), the files are still deleted but the wipe
reports that a protector key may remain; the fallback (`WipeAll`) asks
every known protector to delete its key (a protector with no key present
succeeds without doing anything). A wipe never reports success while a
protector key may remain.

Overwriting in place does not reach copies a journaling or copy-on-write
file system or an SSD may keep; destroying the protector's key does,
where the protector has one.

## Creating over an existing file

`Create` refuses when a state file exists. Replacing one is explicit
(`CreateReplace`). Before anything changes it determines the old
protector (or refuses, changing nothing) and whether the file system can
rename over a file this process holds open (always on POSIX; on Windows
a probe in the state directory, retried briefly when a file is held by
another process such as antivirus). Only a definite "not supported"
answer selects the order of step 3; any other probe failure stops the
replace before anything is wiped. Then:

1. the old protector's key is wiped (if that fails, nothing else
   changes);
2. where an open file can be renamed over: the old file is opened and
   held, the new state is written, renamed into place and flushed, and
   only then are the old bytes overwritten through the held descriptor
   and the descriptor closed;
3. where it cannot (the `MoveFileEx` fallback): the old bytes are
   overwritten through a descriptor that is then closed, and the new
   state is written, renamed into place and flushed. The old file can
   no longer be opened once its key is gone, so nothing is lost by this
   order.

## Nothing to wipe

With no state file, no temporary file and nothing opened, a wipe changes
nothing and reports "nothing to wipe" (`ErrNothingToWipe`), which
`forget` shows as not paired.

In-memory keys are cleared when no longer needed, as far as Go allows;
copies the runtime made cannot be reached.

## Later versions

A change to this format is a new `v` with its own vectors beside the
version 1 vectors, never an edit of them.
