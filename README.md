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
`mcp` (the MCP server with the five LEASH tools); `forget` is listed as
not yet available.

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

## Configuring an MCP client

Give each MCP client its own state directory, and pair it first
(`vettid-agent pair --state-dir DIR`, above). Then add the connector to
the client as a **stdio** server whose command is `vettid-agent` with
the arguments `mcp --state-dir DIR`. Most clients take a JSON entry of
this shape (the file and the name of the top-level member differ from
client to client; see its documentation):

```json
{
  "mcpServers": {
    "vettid": {
      "command": "/usr/local/bin/vettid-agent",
      "args": ["mcp", "--state-dir", "/home/you/.config/vettid-agent/my-client"]
    }
  }
}
```

Clients that add servers from the command line take the same command,
for example `<client> mcp add vettid -- vettid-agent mcp --state-dir
DIR`. Use absolute paths: the client may start the connector in another
directory and with a smaller `PATH`. Where the keys are protected by a
passphrase, add `"--passphrase-file", "/path/to/file"` (a file only you
can read); `mcp` never prompts. Other flags: `--access-minutes N` (the
access session it asks your phone for, default 60) and `--verbose`
(logs each message's type and id, and each tool call's name and
outcome, to standard error, which most clients keep in their MCP log).

The connector speaks MCP versions 2025-11-25, 2025-06-18, 2025-03-26 and
2024-11-05 (a client that asks for a newer one is offered 2025-11-25),
over standard input and output only. It offers these tools:

| Tool | What it does |
|---|---|
| `leash.list_available` | The items you shared with this agent: id, name, category and field labels, never values |
| `leash.request_secret` | An item's values (all fields, or those named) |
| `leash.execute_action` | HMAC-SHA-256 of the agent's data keyed with one field's value, computed in your vault: the value never reaches the agent (preferred where it suffices) |
| `leash.check_status` | The outcome of a request that answered `pending` |
| `leash.connection_info` | The vault and device ids, last contact, access session, grants, whether the agent is paused, whether your vault waits for your daily check |

Every result is a JSON object, as structured content and as the same
JSON in text, with `status` `ok`, `pending` (with a `request_id`) or
`error` (with a stable `code` and a `message`, and `request_id` or
`retry_after` where they apply; the result is then marked as an error).
The codes are your vault's (`forbidden`, `denied`, `approval_timeout`,
`not_found`, `limit`, …) or the connector's own: `access_requested`,
`access_denied`, `vault_unreachable`, `owner_check_required`,
`suspended`, `expired`, `bad_request` and `rate_limited_local`.

The connector answers up to 120 tool calls in a burst and then 2 a
second; calls beyond that get `rate_limited_local` before anything
reaches your vault.
A tool call returns within about 20 seconds; while your vault waits for
your daily check, a tool call makes the connector ask it again at most
once a minute, so that the agent can continue soon after you check in.

An item's values reach the agent's MCP client in one tool result
message, in which **each value appears twice**: in the structured
content and in the text block that repeats the same JSON (MCP
recommends both, and many clients pass only the text to the model). The
connector writes that message once, from one buffer that it zeroes
after the write, and never logs or stores a value. Before it is
collected, a result is kept **in memory for up to 10 minutes** (a
request still waiting for your approval, then for `leash.check_status`)
and zeroed when it is returned or dropped. Buffers outside the MCP
layer are **not** zeroed: the vault client's and the envelope
package's decryption buffers, copies Go's runtime makes, and the pipe
to the client. What the client does with a value (its context, its
logs) is up to the client.

The connector runs at most 64 tool calls at once. A client that stops
reading standard output stops the connector reading standard input,
so it does not grow without bound; until the client reads again, a
written result (and its values) stays in memory.

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
check, it asks for no access (it only asks your vault whether the check
was done, at most once a minute and only when a tool is called).

The connector saves the session your phone grants together with the
message that brought it, including a first session granted with the
pairing. Your vault has no message that tells an agent its current
session, so at start the connector checks a saved, unexpired session
with one request that needs a session (it shows nothing on your phone).
A connector paired by an earlier version, whose first session is not
known, checks the same way before asking for access for the first time.

`vettid-agent status --state-dir DIR` shows what is saved: whether the
connector is paired (its name, device and vault ids), the access session
and the grants as last saved, and how the keys are protected. It does not contact the
vault or the relay and does not take the state directory's lock, so it
can run next to `vettid-agent mcp` and then shows that process's last
saved state. It shows no keys or tokens.

## Requests for items and approvals

The MCP tools reach your items through your vault's LEASH
requests (VAULT-MESSAGING §10.11): the list of items you shared with the
agent, reading an item, and using a field without revealing it (an
HMAC-SHA-256 keyed with the field's value). Your vault decides each
request from the agent's permissions: it answers at once, refuses, or
asks you on your phone first.

- A tool call waits up to 20 seconds in all, including asking your
  vault whether it has an access session. If your vault has not
  answered by then, for example because it is waiting for your approval
  (up to 5 minutes), the tool answers with a request id, and
  `leash.check_status` gives the outcome later. The connector keeps
  waiting for the answer while it runs (also through a pause of up to
  30 seconds while it cannot save its state). A request for access that
  your vault has not answered within the 20 seconds goes on in the
  background; the tool answers "Your vault did not answer…", and the
  next call says access was requested.
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

## Grants

What the agent may do is set on your phone as **grants** (VAULT-MESSAGING
§10.11): each names one permission (reading items you tagged for it, or
one kind of request), whether your phone is asked each time, its limits
an hour and a day, an optional end, and for some permissions the
connections it is limited to. Your vault decides every request; the
connector only keeps track of the grants so that it can show them and
present them.

The connector asks your vault for its grants each time an access
session starts, and keeps the updates your vault sends during the
session. It saves them, so `status` can show them, but it does not rely
on what it saved: until the grants have been read again in the current
access session it presents none. Each grant carries a delegation signed
with your credential key and a short-lived status statement signed by
your vault; the connector checks both, keeps the statement fresh (it
asks for a new one when less than a quarter of its lifetime, and at
least a minute, remains), and never presents a grant that your vault no
longer lists, that has ended, or anything at all while your vault has
paused the agent after repeated refused requests ("suspended"; you
resume it on your phone).

Messages from your vault can arrive out of order, so only the answer to
a list the connector sent, with nothing learned while it was on its
way, can add a grant, bring back a removed one or end a pause. Every
update, and any other list answer, can only take grants away or pause
the agent; the connector then asks for the grants again, and that list
brings what the update added. A pause ends only when a list sent after
it says so.

In the background the connector refreshes a statement only for a grant
it was asked to present in the last 15 minutes, at most once a minute;
other statements are refreshed when they are needed.

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
