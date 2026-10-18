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
in small phases. Today the binary has `pair`, `version`, `status` and
`mcp` (which keeps the vault connection; its MCP tools come later);
`forget` is listed as not yet available.

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

## Pairing

On your phone, open Devices & agents and choose Pair an agent; then, on
the computer where the agent runs:

```sh
vettid-agent pair --state-dir ~/.config/vettid-agent/my-client
```

and paste the code when asked (or give it as the last argument, or on
standard input; a code on the command line can be seen by other users
of the computer while the command runs). The code, its link form
`https://…/connect#…` and `vettid://connect#…` are all accepted, also
inside surrounding text. Each MCP client gets its own state directory,
and so its own pairing, which your phone lists and removes separately.

The connector shows a six-digit code: approve on your phone only if the
phone shows the same one. It then waits up to 10 minutes for your
decision. `--name` sets the name your phone shows (default "Agent on
<host name>"). Everything is written to standard error; the pairing code
is never written anywhere, and the six-digit code only to your terminal.

The keys are protected as described below: the TPM on Linux, DPAPI on
Windows, a passphrase where there is neither (macOS until its Keychain
protector exists). A TPM or DPAPI that is present but does not work
makes `pair` stop with the cause and the fix; `--passphrase` chooses
the passphrase protector instead (not bound to this computer).

If the wait is interrupted after the six-digit code was shown, the keys
are kept: run `vettid-agent pair --state-dir …` again, without a code,
before the 10 minutes end, and it keeps waiting with the same keys
(approve only if your phone shows the code shown earlier). Run it with
a new code instead, or interrupt it before the six-digit code is shown,
and the unfinished pairing is discarded; a new pairing always uses new
keys. A rejection on the phone, or the end of the 10 minutes, deletes
the unfinished pairing. A state directory that holds a completed
pairing is not paired again unless you add `--restart` (then remove the
old pairing on your phone).

The connector gives up at the end of its 10 minutes, measured from just
before it creates its keys, so it stops no later than your vault. If
you approve on the phone in the seconds after the connector gave up,
the phone lists an agent whose keys no longer exist: unlink it in
Devices & agents. The same applies if the connector reports that it
could not save its keys after your approval.

Codes are accepted only for relays reached over HTTPS, and the relay
named in the code must be the vault's relay recorded in the invitation
the code commits to; a code whose relay was changed is refused before
its six-digit code is shown. Builds with the `devstack` tag (for
vettid-vault's local dev stack, never a release) also accept a
plain-HTTP relay on a loopback address.

## Running for an MCP client

The MCP client starts the connector itself, for example with the command
`vettid-agent mcp --state-dir ~/.config/vettid-agent/my-client` (and
`--passphrase-file PATH` or `--passphrase-fd N` where the keys are
protected by a passphrase: `mcp` never asks on the terminal, because its
standard input carries MCP messages). It holds the state directory's
lock while it runs (a second one on the same directory exits with "in
use by another agent app"), stays connected to your vault, and exits
when the client closes its standard input. Standard output carries only
MCP messages; notices go to standard error (`--verbose` adds each
message's type and id, never its contents).

While it runs it collects what the vault sent and saves its state before
telling the relay a message was received, so that a crash never loses a
key change or a token: what was not saved is collected again (a save
that keeps failing, such as on a full disk, is retried with a pause of
up to 30 seconds, and logged once when it starts failing and once when
it works again). It asks the vault for its status when it starts and
every 6 hours, rather than relying on having seen every notice.

If you remove the agent on your phone, the vault tells the connector,
which deletes its keys from this computer and exits saying so (if the
deletion fails, run it again to retry, or delete the state directory:
the protectors of this version keep no key outside it). If the relay
refuses the agent, it collects what is still waiting for up to a minute
in case that notice is among it, then exits saying so and keeps its
keys; `vettid-agent forget` (to come) deletes them.

## Access sessions and `status`

The agent acts only within an access session that you allow on your
phone (VAULT-MESSAGING §6.8). When a tool call needs one and there is
none, the connector asks your vault for access (one hour, or what
`--access-minutes` of `vettid-agent mcp` sets) and the tool
answers "This agent needs access to your vault. Allow it on your phone,
then try again." It never asks more than once at a time, waits 10
minutes after you decline or leave a request unanswered, asks at most 6
times an hour, and waits as long as your vault says when it answers that
the last request was too recent. While your vault waits for your daily
check, it asks for nothing.

The connector saves the session your phone grants together with the
message that brought it, including a first session granted with the
pairing. Your vault has no message that tells an agent its current
session, so at start the connector checks a saved, unexpired session
with one request that needs a session (it shows nothing on your phone).
A connector paired by an earlier version, whose first session is not
known, checks the same way before asking for access for the first time.

`vettid-agent status --state-dir DIR` shows what is saved: whether the
connector is paired (its name, device and vault ids), the access session
as last saved, and how the keys are protected. It does not contact the
vault or the relay and does not take the state directory's lock, so it
can run next to `vettid-agent mcp` and then shows that process's last
saved state. It shows no keys or tokens.

## Requests for items and approvals

The MCP tools (to come) reach your items through your vault's LEASH
requests (VAULT-MESSAGING §10.11): the list of items you shared with the
agent, reading an item, and using a field without revealing it (an
HMAC-SHA-256 keyed with the field's value). Your vault decides each
request from the agent's permissions: it answers at once, refuses, or
asks you on your phone first.

- A tool call waits up to 20 seconds. If your vault has not answered by
  then, for example because it is waiting for your approval (up to 5
  minutes), the tool answers with a request id, and
  `leash.check_status` gives the outcome later. The connector keeps
  waiting for the answer while it runs.
- A request that gets no answer is sent again, at most twice, as the
  same message, so that your vault answers the copy instead of running
  it again. A request your vault answered (refused, declined on your
  phone, timed out, or anything else) is never sent again on its own.
- If your vault does not answer within 30 seconds, `leash.check_status`
  says "Your vault did not answer. It may be locked; unlock it on your
  phone." and the request stays open.
- Results are kept in memory for at most 10 minutes and returned once;
  an item's values are zeroed in memory once passed to the agent or
  dropped. Nothing of a request is written to the state file, so a
  result does not survive a restart of the connector: the agent asks
  again.
- Logs carry the kind of request, its id and the vault's error code,
  never an item's name or values.

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

## Keys at rest on Windows: DPAPI

On Windows the connector encrypts its state file's key with DPAPI in
user scope (`CryptProtectData`), so it opens only for the Windows user
who paired the connector, on this computer. Another user of the
computer cannot open it from the file alone; an administrator controls
the computer, though, and while you are logged on can obtain your DPAPI
keys from Windows' memory. Any program running as you can open it, as it
can read the state file: DPAPI protects you from other users and from a
copy of the file taken elsewhere, not from programs you run.

Exceptions that come with Windows itself:

- with a roaming profile (some company networks), the key also opens on
  the other computers of the network where your profile is loaded;
- in an Active Directory domain, the domain's DPAPI backup key, held by
  the domain controllers, can recover a domain user's keys;
- if an administrator resets your Windows password (rather than you
  changing it), Windows can no longer open keys made before, and the
  connector says so; set the old password back if you can, or pair
  again.

When Windows cannot use the key it needs, the connector first asks you
to check that you are signed in as the user who paired it, with your
profile loaded and, for a domain account, the domain reachable (a
domain controller out of reach or a roaming profile not yet synced can
cause this for a while); pair again only if it persists.

If DPAPI does not work in the logon the connector runs in (for example
a service or scheduled task without your loaded profile or stored
password), the connector says what is wrong and how to fix it, and uses
a passphrase only if you ask for one.

The encrypted key lives only inside the state file. `forget` overwrites
and deletes that file, but an old copy recovered from the disk
afterwards (a backup, a file system snapshot, a block an SSD remapped)
can still be opened by your Windows user on this computer for as long as
your DPAPI keys exist. Opening such a copy needs the copy (from a
backup, a snapshot or the raw disk) and your Windows logon.

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
