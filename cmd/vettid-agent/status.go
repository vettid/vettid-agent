package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/vettid/vettid-agent/internal/access"
	"github.com/vettid/vettid-agent/internal/pairing"
	"github.com/vettid/vettid-agent/internal/protect"
	"github.com/vettid/vettid-agent/internal/state"
)

// statusResolve replaces the protector resolver (tests' protector).
var statusResolve state.Resolver

const statusUsage = `Usage: vettid-agent status --state-dir DIR [--passphrase-fd N | --passphrase-file PATH]

Shows the pairing, access and grants saved in DIR. It does not contact your
vault or its relay, and does not take the state directory's lock, so it
can run while ` + "`vettid-agent mcp`" + ` runs for DIR; it then shows that
process's last saved state.

Flags:
`

func runStatus(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("state-dir", "", "the state `DIR`ectory (required)")
	prot := &pairing.Protectors{}
	prot.Source.AddFlags(fs)
	fs.Usage = func() {
		fmt.Fprint(stderr, statusUsage)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if *dir == "" || fs.NArg() != 0 {
		fs.Usage()
		return 2
	}
	defer prot.Clear()
	resolve := state.Resolver(prot.Resolve)
	if statusResolve != nil {
		resolve = statusResolve
	}
	v, err := state.ReadOnly(*dir, resolve)
	if errors.Is(err, state.ErrNotFound) {
		fmt.Fprintf(stdout, "State directory: %s\nNot paired. Run `vettid-agent pair --state-dir %s`.\n", *dir, *dir)
		return 0
	}
	if err != nil {
		if rerr := prot.ResolveErr(); rerr != nil {
			err = rerr
		}
		fmt.Fprintf(stderr, "vettid-agent status: the state file cannot be read: %v\n", err)
		return 1
	}
	rec, err := pairing.DecodeRecord(v.State)
	clear(v.State)
	if err != nil {
		fmt.Fprintf(stderr, "vettid-agent status: %v\n", err)
		return 1
	}
	writeStatus(stdout, *dir, v, rec, time.Now())
	clear(rec.Device)
	return 0
}

// writeStatus prints the view: identifiers and times only, never keys,
// tokens or the state itself.
func writeStatus(w io.Writer, dir string, v *state.View, rec *pairing.Record, now time.Time) {
	var dev struct {
		Name     string `json:"name"`
		VaultID  string `json:"vault_id"`
		DeviceID string `json:"device_id"`
	}
	_ = json.Unmarshal(rec.Device, &dev)
	fmt.Fprintf(w, "State directory: %s\n", dir)
	switch rec.Phase {
	case pairing.PhasePaired:
		// Stored strings came from the vault or the operator: shown
		// without control or format characters.
		fmt.Fprintf(w, "Paired: yes, as \"%s\" (device %s of vault %s), on %s\n", pairing.Sanitize(dev.Name),
			pairing.Sanitize(dev.DeviceID), pairing.Sanitize(dev.VaultID), v.CreatedAt.Local().Format("2006-01-02 15:04"))
		fmt.Fprintf(w, "Access session: %s (as last saved; the vault is not contacted)\n", access.Describe(rec.Access, now))
		writeGrants(w, rec.Leash, now)
	case pairing.PhaseWaiting:
		if now.Before(rec.Deadline) {
			fmt.Fprintf(w, "Paired: not yet; waiting for approval on your phone until %s (run `vettid-agent pair` to keep waiting)\n", rec.Deadline.Local().Format("15:04"))
		} else {
			fmt.Fprintln(w, "Paired: no; an unfinished pairing timed out (the next `vettid-agent pair` discards it)")
		}
	default:
		fmt.Fprintln(w, "Paired: no; an unfinished pairing (the next `vettid-agent pair` discards it)")
	}
	switch v.Protector {
	case protect.PassphraseName:
		fmt.Fprintf(w, "Keys: %s\n", protect.NotMachineBound)
	default:
		fmt.Fprintf(w, "Keys: protected by %s, bound to this computer\n", protectorLabel(v.Protector))
	}
	fmt.Fprintln(w, "Read without taking the state directory's lock: if `vettid-agent mcp` runs for it, this is its last saved state.")
}

func protectorLabel(name string) string {
	switch name {
	case "tpm":
		return "the TPM"
	case "dpapi":
		return "Windows DPAPI for this user"
	default:
		return fmt.Sprintf("%q", pairing.Sanitize(name))
	}
}
