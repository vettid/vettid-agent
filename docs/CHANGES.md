# Changes

What a release changes for the person running the connector, for its
release notes. Newest first.

## Not yet released

- **`pair --name` changed meaning.** The name your phone shows for the
  agent is now set with `--label` (default "Agent on <host name>").
  `--name` now names a pairing whose connector runs as a service in an
  account of its own (AGENT-PLAN AG14), as `mcp`, `status` and `forget`
  take it. A script that ran `vettid-agent pair --state-dir DIR --name
  "My agent"` must use `--label "My agent"`.
- `vettid-agent status` adds a line: runs and proxies are off while the
  connector runs in the agent's own account.
