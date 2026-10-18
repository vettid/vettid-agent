//go:build devstack

package pairing

// A devstack build (AGENT-PLAN §4.8; the dev-stack harness and its
// tests) may pair through a plain-HTTP relay on a loopback address, as
// vettid-vault's local dev stack offers. Release builds are never built
// with this tag.
func init() { allowHTTPRelay = true }
