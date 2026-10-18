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

## What the state holds

The plaintext under the data key is the connector's record
(`internal/pairing`, `Record`), compact JSON:

```
{"v":1,"phase":"started"|"waiting"|"paired","deadline":"<RFC 3339>","device":{…},
 "access":{"state":"none"|"active","session_id":"…","expires_at":"<RFC 3339>"},
 "leash":{"v":1,"as_of":"<RFC 3339>","suspended":false,"grants":[…]}}
```

| Member | What |
|---|---|
| `v` | 1 |
| `phase` | `started`: fresh keys, mailbox registered, no SAS shown yet (discarded by the next `pair`); `waiting`: the handshake completed and the SAS was shown, the connector waits for the owner's decision (resumable until `deadline`); `paired`: `device.paired` arrived |
| `deadline` | present exactly while `phase` is `started` or `waiting`: the end of the 10 minutes after `hs.init` (VAULT-MESSAGING §6.7), measured from just before the keys were created |
| `device` | the vault client's `Save()` output: the `ik`, `kem` and relay-key seeds, the vault record with tokens, the session keyring |
| `access` | optional, `paired` only: the access session (VAULT-MESSAGING §6.8) as of this save. `state` is `none` or `active`. An `active` one has `session_id` and `expires_at` (from `device.session.granted`), `expires_at` only (the first session, from `device.paired`'s `session_expires_at`, which comes with no session id), or neither (a session found by a check whose end is not known). Absent means not known: after a pairing whose `device.paired` gave no usable `session_expires_at`, and in records paired by a build before the first session was recorded. `unknown` is never written |
| `leash` | optional, `paired` only: the LEASH grants (VAULT-MESSAGING §10.11) as the vault last sent them, kept by `internal/leash`: `v` 1; `as_of`, when the vault sent them; `suspended`, the vault's flag; `grants`, each grant in its wire form (`grant_id`, `agent_id`, `version`, `scope`, `approval`, `connections`, `tags`, `match`, `access`, `uses`, `per_hour`, `per_day`, `expires_at`, `status_ttl`, `issued_at`, `delegation`, `sig`) without its status statement. Absent until the first grant set arrives |

It is parsed strictly (no unknown members, nothing after it). The
pairing code and the SAS are never stored.

`access` is first written by `internal/pairing` from `device.paired`
(kept by the vault client, `Paired().SessionExpiresAt`; without a usable
time it stays absent, since the client keeps a missing and a malformed
`session_expires_at` alike, and the first need checks it with the
vault), then by
`internal/vaultconn` in the same save as the batch that carried
`device.session.granted` or `.ended`, before that batch is acknowledged
at the relay, so a crash cannot lose a grant or
an end that the relay has dropped; applying the same events again gives
the same result. What `internal/access` learns from a check
(`leash.grant.list` answered or `session_required`) is set only if the
session is still the one the check started from (an atomic
compare-and-set, so a grant or an end saved in between is never
overwritten), and saved with the next batch. The version stays 1: the member is optional, and a record
without it reads as before. A build older than this member refuses a
record that has it (strict parsing); no such build was released.

`leash` is written the same way: `leash.grant.updated` and the answer
to `leash.grant.list` are applied in the save of their batch, before it
is acknowledged. Their order is not relied on (VAULT-MESSAGING §8.4 gives
none, and §8.3 sends a failed deposit again later): a set replaces the
grants only if it is the answer to a list this process sent with nothing
learned since; anything else (every `leash.grant.updated` included) may
only remove grants or suspend, and a fresh list is asked for. A
status statement (`leash.status.get`) and what a refused one teaches
(`not_found`, a suspension) are kept in memory and saved with the next
batch; statements are never saved, since a grant is presented only
after the grants were listed again in the current access session, and
that list carries fresh ones. The member is parsed strictly and each
grant is checked as when it arrived (its device id, its delegation's
signature and members); a member that fails is ignored and replaced by
the next grant set. A build older than this member refuses a record
that has it; no such build was released.

### Pairing's last batch

`vettid-agent pair` saves and acknowledges the batch that carried
`device.paired`, so any message that arrived after it in the same batch
is acknowledged by `pair` and never reaches `internal/vaultconn`.
Nothing is lost: the first access session comes from `device.paired`
itself, grants are fetched with `leash.grant.list` at each session
start (AGENT-PLAN §4.5), and the vault client applies its own messages
(tokens, rekeys) while handling them, whichever command collects.

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

A failure says what it left (the caller decides from that, never from
which protector the store holds): no sentinel means nothing was changed
(an `Exists` error, the protector or the probe, or the old key's wipe);
`ErrReplaceIncomplete` means the old key was wiped (and possibly the old
bytes overwritten) but the new file is not in place, so the old state
may be gone; `ErrReplacedPartly` (or `ErrNotDurable`) means the new file
is in place and the old one gone.

## Nothing to wipe

With no state file, no temporary file and nothing opened, a wipe changes
nothing and reports "nothing to wipe" (`ErrNothingToWipe`), which
`forget` shows as not paired.

In-memory keys are cleared when no longer needed, as far as Go allows;
copies the runtime made cannot be reached.

## Later versions

A change to this format is a new `v` with its own vectors beside the
version 1 vectors, never an edit of them.
