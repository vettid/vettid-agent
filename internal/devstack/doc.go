// Package devstack connects the connector to vettid-vault's local dev
// stack (AGENT-PLAN §4.8, §6 A2.4 and A3.4) and holds the dev-stack
// tests.
//
// Everything in it but this file is built only with the `devstack` build
// tag, which release builds never carry (the release check refuses a
// binary built with any tag). Without the tag the package is empty and
// the connector cannot be pointed at anything but the relay a pairing
// code names.
//
// With the tag:
//
//   - relay.go maps the dev stack's relay origin (`https://relay.vettid.test`,
//     the origin its tokens name) to the stack's TLS front on the
//     loopback interface, trusting only the TEST TLS root the stack's
//     control port serves at `GET /dev/trust`. `vettid-agent` built with
//     the tag uses it when VETTID_AGENT_DEVSTACK names the control port
//     (cmd/vettid-agent/devstack.go).
//   - the _test.go files are the harness: they find the dev stack that
//     runs, or start one (one at a time, from a vettid-vault checkout),
//     play the member's app with the stack's `vaultctl`, and run the
//     connector binary built with the tag, as an operator and an MCP
//     client would (`make devstack-test`).
package devstack
