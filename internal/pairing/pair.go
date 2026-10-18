package pairing

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/vettid/vettid-relay/relayclient"
	"github.com/vettid/vettid-vault/client"
	"github.com/vettid/vettid-vault/vms/invite"

	"github.com/vettid/vettid-agent/internal/state"
)

// Window is how long the connector waits after its hs.init for the
// owner's decision (VAULT-MESSAGING §6.7, 0.10.4, 0.10.5). The vault
// drops the pairing at the same time; the connector measures from just
// before it creates its keys, so it stops no later than the vault.
// Tests shorten it.
var Window = 10 * time.Minute

// MaxNameBytes is the longest name sent: the vault keeps the first 128
// bytes of a device's self-asserted name.
const MaxNameBytes = 128

// Options configure Pair.
type Options struct {
	// Store is the state directory, opened (and so locked) by the caller.
	Store *state.Store
	// Resolve gives the protector for an existing state file's header.
	Resolve state.Resolver
	// ResolveErr, if set, says why Resolve returned nil (a passphrase
	// that could not be read), or returns nil.
	ResolveErr func() error
	// AllProtectors are every protector this build knows, for
	// state.Store.WipeAll when an existing state file's protector cannot
	// be determined and Restart is set.
	AllProtectors []state.Protector
	// Protector picks and prepares the protector for a new pairing. It
	// is called before the relay is contacted; notice, if not empty, is
	// shown to the operator (for example that a passphrase is not bound
	// to this computer).
	Protector func() (p state.Protector, notice string, err error)
	// Code returns the text that holds the pairing code. It is called
	// only when a new pairing starts.
	Code func() (string, error)
	// CodeGiven: the operator gave a code on the command line, so an
	// interrupted pairing is discarded instead of resumed.
	CodeGiven bool
	// CodeOnStdin: standard input is not a terminal, so it may hold a
	// code; a resume says that it is not read.
	CodeOnStdin bool
	// PassphraseChosen: the operator gave --passphrase; a resume says
	// that it does not change the saved pairing's protector.
	PassphraseChosen bool
	// Restart discards whatever the state directory holds, including a
	// completed pairing or a state file that does not open.
	Restart bool
	// Name is the self-asserted name (AGENT-PLAN §2 AG11); "" means
	// DefaultName().
	Name string
	// Out is the operator's terminal (standard error).
	Out io.Writer

	// HTTP, Now and PollWait are passed to the client (tests; nil and
	// zero mean the client's defaults and time.Now).
	HTTP     *http.Client
	Now      func() time.Time
	PollWait time.Duration
}

// Outcomes. Their texts are those of AGENT-PLAN §11; the caller shows
// them as they are.
var (
	ErrRejected = errors.New(TextRejected)
	ErrExpired  = errors.New(TextExpired)
	// ErrInterrupted: the operator interrupted Pair. The error's text
	// says whether the pairing can be resumed.
	ErrInterrupted = errors.New("pairing interrupted")
	// ErrRelayMismatch: the code's relay is not the vault's relay in the
	// bundle the code commits to.
	ErrRelayMismatch = errors.New("the relay named in the pairing code is not your vault's relay (the code was altered); nothing was kept. Start again from your phone, and copy the code directly")
	// ErrAlreadyPaired: the state directory holds a completed pairing.
	ErrAlreadyPaired = errors.New("this connector is already paired with a vault (this state directory holds its keys); to pair this state directory again, run `vettid-agent pair --restart`, and remove the old pairing on your phone")
)

// interrupted is an ErrInterrupted with the operator text.
type interrupted struct{ text string }

func (e *interrupted) Error() string        { return e.text }
func (e *interrupted) Is(target error) bool { return target == ErrInterrupted }

// DefaultName returns "Agent on <host name>" (AGENT-PLAN §2 AG11),
// shortened to MaxNameBytes.
func DefaultName() string {
	h, err := os.Hostname()
	h = strings.TrimSpace(h)
	if err != nil || h == "" || CheckName("Agent on "+h) != nil {
		return "Agent"
	}
	return truncateUTF8("Agent on "+h, MaxNameBytes)
}

// CheckName checks an operator's name for the connector (chosen; not in
// the spec): 1 to MaxNameBytes bytes of UTF-8, no control characters,
// no format characters (Unicode category Cf: direction overrides,
// zero-width characters), no leading or trailing space.
func CheckName(name string) error {
	switch {
	case name == "":
		return errors.New("the name is empty")
	case len(name) > MaxNameBytes:
		return fmt.Errorf("the name is longer than %d bytes", MaxNameBytes)
	case !utf8.ValidString(name):
		return errors.New("the name is not valid UTF-8")
	case strings.TrimSpace(name) != name:
		return errors.New("the name starts or ends with white space")
	}
	for _, r := range name {
		if unicode.IsControl(r) || r == '\u2028' || r == '\u2029' {
			return errors.New("the name contains a control character")
		}
		if unicode.Is(unicode.Cf, r) {
			return errors.New("the name contains an invisible formatting character (such as a direction override)")
		}
	}
	return nil
}

func truncateUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return strings.TrimSpace(s[:n])
}

// FormatSAS returns the six-digit SAS as "123 456". Anything else is an
// error (fail secure: never show a malformed code to compare).
func FormatSAS(sas string) (string, error) {
	if len(sas) != 6 {
		return "", errors.New("the handshake did not give a six-digit code")
	}
	for i := 0; i < 6; i++ {
		if sas[i] < '0' || sas[i] > '9' {
			return "", errors.New("the handshake did not give a six-digit code")
		}
	}
	return sas[:3] + " " + sas[3:], nil
}

// store is what Pair uses of *state.Store; tests wrap it to inject
// failures.
type store interface {
	Exists() (bool, error)
	Load(state.Resolver) ([]byte, error)
	Create(state.Protector, []byte) error
	CreateReplace(state.Protector, []byte, state.Resolver) error
	Save([]byte) error
	Wipe(state.Resolver) error
	WipeAll([]state.Protector) error
	Dir() string
}

// wrapStore is the identity outside tests.
var wrapStore = func(s store) store { return s }

// run is one Pair call.
type run struct {
	o  Options
	st store
	// replacing says what the first write replaces ("unfinished",
	// "paired" or "unreadable"); replaced is set once it did.
	replacing string
	replaced  bool
	prot      state.Protector // the new pairing's protector
	created   bool            // the state file now holds this run's record
	replace   bool            // a state file exists and is replaced at the first write
}

// Pair runs `vettid-agent pair` (AGENT-PLAN §4.3):
//
//   - The state directory holds a completed pairing: ErrAlreadyPaired,
//     unless Restart.
//   - It holds a pairing interrupted after its SAS was shown, the wait
//     has not ended, no code was given and Restart is not set: the wait
//     is resumed with the saved keys (the SAS is not stored, so it is
//     not shown again).
//   - Anything else unfinished is discarded (wiped) when the new
//     pairing first writes its state; a state file that does not open
//     is discarded only with Restart.
//
// A new pairing: read and check the code; prepare the protector; create
// the device with fresh keys (client.New, role agent) and save
// (started); run the handshake (Pair) and save (waiting) before the SAS
// is shown; wait for device.paired, device.pair.rejected or the end of
// Window and save (paired), or wipe the state on a rejection, the
// timeout or any failure. An interruption before the SAS is shown wipes
// the state; one after it keeps it for a resume.
func Pair(ctx context.Context, o Options) error {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Name == "" {
		o.Name = DefaultName()
	}
	if err := CheckName(o.Name); err != nil {
		return err
	}
	r := &run{o: o, st: wrapStore(o.Store)}
	exists, err := r.st.Exists()
	if err != nil {
		return err
	}
	if exists {
		rec, err := r.loadExisting()
		if err != nil {
			return err
		}
		if rec != nil {
			return r.resume(ctx, rec)
		}
	}
	err = r.pairNew(ctx)
	if err != nil && r.replace && !r.replaced {
		// The new pairing failed before its first write: whatever the
		// state directory held is still there.
		fmt.Fprintln(o.Out, textKept)
	}
	return err
}

// loadExisting looks at an existing state file. It returns a record to
// resume, nil to start a new pairing over it, or an error.
func (r *run) loadExisting() (*Record, error) {
	o := r.o
	raw, err := r.st.Load(o.Resolve)
	var rec *Record
	if err == nil {
		rec, err = DecodeRecord(raw)
		clear(raw)
	}
	if err != nil && o.ResolveErr != nil {
		if rerr := o.ResolveErr(); rerr != nil {
			err = rerr
		}
	}
	if err != nil {
		if !o.Restart {
			return nil, fmt.Errorf("the state directory %s holds a state file that cannot be opened (%w); to discard it and pair again, run `vettid-agent pair --restart`", r.st.Dir(), err)
		}
		r.replace, r.replacing = true, "unreadable"
		return nil, nil
	}
	r.replace = true
	switch {
	case rec.Phase == PhasePaired && !o.Restart:
		return nil, ErrAlreadyPaired
	case rec.Phase == PhasePaired:
		r.replacing = "paired"
		return nil, nil
	case rec.Phase == PhaseWaiting && !o.Restart && !o.CodeGiven:
		if o.Now().Before(rec.Deadline) {
			return rec, nil
		}
		// The wait ended while nothing ran.
		if err := r.st.Wipe(o.Resolve); err != nil {
			return nil, fmt.Errorf("%s The unfinished pairing could not be deleted (%w); it is discarded at the next pairing.", TextExpired, err)
		}
		return nil, ErrExpired
	default:
		r.replacing = "unfinished"
		return nil, nil
	}
}

// resume continues waiting for an approval with saved keys.
func (r *run) resume(ctx context.Context, rec *Record) error {
	o := r.o
	var st client.State
	if err := json.Unmarshal(rec.Device, &st); err != nil || st.Role != "agent" || st.Vault == nil || st.DeviceID != "" {
		// Not wiped: a state that does not look as expected is never
		// destroyed without the operator asking.
		return errors.New("the saved pairing is not a pending agent pairing; to discard it, run `vettid-agent pair --restart`")
	}
	d, err := client.Load(r.clientConfig(client.Config{}), rec.Device)
	if err != nil {
		return errors.New("the saved pairing could not be restored; to discard it, run `vettid-agent pair --restart`")
	}
	r.created = true
	fmt.Fprintf(o.Out, textResume+"\n", rec.Deadline.Local().Format("15:04"))
	if o.CodeOnStdin {
		fmt.Fprintln(o.Out, textResumeStdin)
	}
	if o.PassphraseChosen {
		fmt.Fprintln(o.Out, textResumePassphrase)
	}
	fmt.Fprintln(o.Out, TextWaiting)
	return r.wait(ctx, d, rec)
}

func (r *run) clientConfig(c client.Config) client.Config {
	c.HTTP, c.Now, c.PollWait = r.o.HTTP, r.o.Now, r.o.PollWait
	return c
}

func (r *run) pairNew(ctx context.Context) error {
	o := r.o
	text, err := o.Code()
	if err != nil {
		return err
	}
	code, err := ParseCode(text, o.Now())
	if errors.Is(err, ErrCodeExpired) {
		return ErrExpired
	}
	if err != nil {
		return err
	}
	p, notice, err := o.Protector()
	if err != nil {
		return err
	}
	r.prot = p
	if notice != "" {
		fmt.Fprintln(o.Out, notice)
	}
	fmt.Fprintln(o.Out, textContacting)

	rec := &Record{Phase: PhaseStarted, Deadline: o.Now().Add(Window)}
	wctx, cancel := deadlineCtx(ctx, rec.Deadline, o.Now())
	defer cancel()
	d, err := client.New(wctx, r.clientConfig(client.Config{Role: "agent", Name: o.Name, RelayURL: code.Relay}))
	if err != nil {
		// Nothing was written yet.
		return r.pairError(ctx, wctx, code, err)
	}
	if err := r.save(d, rec); err != nil {
		// Also a write that is in place but not durable: nothing of
		// this pairing is kept.
		return r.failWipe(err)
	}
	sas, err := d.Pair(wctx, code.Link)
	if err != nil {
		return r.failWipe(r.pairError(ctx, wctx, code, err))
	}
	// The device's own mailbox is on the code's `r`; the vault's relay
	// is the one in the bundle the code's hash commits to. The vault
	// writes the same URL into both, so a difference means `r` was
	// altered (the handshake and the SAS would still be genuine), and the
	// connector would keep its mailbox on another relay (AGENT-PLAN
	// §4.7). Checked before anything is saved as waiting or shown.
	if vurl, _ := d.VaultMailbox(); vurl == "" || strings.TrimRight(vurl, "/") != strings.TrimRight(code.Relay, "/") {
		return r.failWipe(ErrRelayMismatch)
	}
	shown, err := FormatSAS(sas)
	if err != nil {
		return r.failWipe(err)
	}
	// Saved before the SAS is shown: a shown SAS always has a resumable
	// state behind it.
	rec.Phase = PhaseWaiting
	if err := r.save(d, rec); err != nil {
		return r.failWipe(err)
	}
	fmt.Fprintf(o.Out, textSAS+"\n", shown)
	fmt.Fprintln(o.Out, TextWaiting)
	return r.wait(ctx, d, rec)
}

// wait waits for the owner's decision until rec.Deadline.
func (r *run) wait(ctx context.Context, d *client.Device, rec *Record) error {
	o := r.o
	wctx, cancel := deadlineCtx(ctx, rec.Deadline, o.Now())
	defer cancel()
	err := d.AwaitPaired(wctx)
	switch {
	case err == nil:
		rec.Phase, rec.Deadline = PhasePaired, time.Time{}
		if err := r.save(d, rec); err != nil {
			if errors.Is(err, state.ErrNotDurable) {
				fmt.Fprintln(o.Out, TextPaired)
				fmt.Fprintf(o.Out, "Warning: the state file is in place but could not be flushed to disk (%v); it may not survive a power loss.\n", err)
				return nil
			}
			// A `waiting` file left behind would be resumed for an
			// approval that already came: delete it.
			return r.failWipe(fmt.Errorf("your phone approved this agent, but its keys could not be saved (%w), so this computer cannot use the pairing; its unfinished state is deleted. Unlink the agent on your phone (Devices & agents) and pair again", err))
		}
		fmt.Fprintln(o.Out, TextPaired)
		return nil
	case errors.Is(err, client.ErrPairRejected):
		return r.failWipe(ErrRejected)
	case ctx.Err() != nil:
		return &interrupted{fmt.Sprintf(textInterrupted, rec.Deadline.Local().Format("15:04"))}
	case wctx.Err() != nil:
		return r.failWipe(ErrExpired)
	default:
		return r.failWipe(errors.New("your vault's answer could not be read; start again from your phone"))
	}
}

// save writes rec with the device's current state: the first write of
// a new pairing creates the state file (replacing what was there), later
// ones save under the same data key. A write that is in place but not
// flushed is saved once more.
func (r *run) save(d *client.Device, rec *Record) error {
	dev, err := d.Save()
	if err != nil {
		return fmt.Errorf("the pairing state could not be prepared for saving: %w", err)
	}
	rec.Device = dev
	b, err := rec.Encode()
	clear(dev)
	if err != nil {
		return err
	}
	defer clear(b)
	err = r.write(b)
	if errors.Is(err, state.ErrNotDurable) {
		err = r.st.Save(b)
	}
	if err != nil && !errors.Is(err, state.ErrNotDurable) {
		return fmt.Errorf("the pairing state could not be saved: %w", err)
	}
	return err
}

func (r *run) write(b []byte) error {
	o := r.o
	if r.created {
		return r.st.Save(b)
	}
	var err error
	if r.replace {
		err = r.st.CreateReplace(r.prot, b, o.Resolve)
		if errors.Is(err, state.ErrProtectorUnknown) && o.Restart {
			if err = r.st.WipeAll(o.AllProtectors); err == nil {
				err = r.st.Create(r.prot, b)
			}
		}
	} else {
		err = r.st.Create(r.prot, b)
	}
	if err == nil || errors.Is(err, state.ErrNotDurable) {
		r.created = true
		if r.replace && !r.replaced {
			// Said only now that the old state is gone.
			r.replaced = true
			switch r.replacing {
			case "paired":
				fmt.Fprintln(o.Out, textReplaced)
			case "unreadable":
				fmt.Fprintln(o.Out, textDiscardedUnreadable)
			default:
				fmt.Fprintln(o.Out, textDiscarded)
			}
		}
	}
	return err
}

// failWipe deletes this run's state (nothing of a failed pairing is
// kept: a new pairing always uses new keys) and returns err, with the
// wipe's failure added if there was one.
func (r *run) failWipe(err error) error {
	if !r.created {
		return err
	}
	if werr := r.st.Wipe(r.o.Resolve); werr != nil && !errors.Is(werr, state.ErrNothingToWipe) {
		return fmt.Errorf("%w\nThe unfinished pairing's state could not be deleted (%v); it is discarded at the next pairing.", err, werr)
	}
	r.created = false
	return err
}

// pairError maps a failure of client.New or Pair to an operator error,
// never containing the code.
func (r *run) pairError(ctx, wctx context.Context, code *Code, err error) error {
	var re *relayclient.Error
	switch {
	case ctx.Err() != nil:
		return &interrupted{textInterruptedEarly}
	case wctx.Err() != nil, errors.Is(err, invite.ErrExpired):
		return ErrExpired
	case errors.Is(err, invite.ErrHash):
		return errors.New("the pairing code does not match the invitation your vault left at its relay (it was mistyped or altered); start again from your phone")
	case errors.Is(err, invite.ErrDecrypt), errors.Is(err, invite.ErrBundle), errors.Is(err, invite.ErrKind):
		return errors.New("the invitation behind this pairing code could not be opened (the code was mistyped or altered); start again from your phone")
	case errors.As(err, &re) && re.Status == http.StatusNotFound:
		return errors.New("the pairing code was already used or has expired; start again from your phone")
	case errors.As(err, &re):
		// Only the status and a cleaned error code: the relay's own text
		// is not shown, so a relay cannot write lines to the terminal.
		return fmt.Errorf("your vault's relay refused the request (HTTP %d, %s); start again from your phone", re.Status, sanitize(redact(re.Code, code.secrets()...)))
	case errors.Is(err, client.ErrProtocol):
		return errors.New("the handshake with your vault failed; start again from your phone")
	default:
		return fmt.Errorf("could not pair through your vault's relay: %s", sanitize(redact(err.Error(), code.secrets()...)))
	}
}

// maxShownError is the most of a foreign error text shown, in bytes.
const maxShownError = 200

// sanitize makes text from outside (a relay) safe to show on one
// terminal line: control characters (escape sequences, line breaks),
// Unicode format characters (bidirectional overrides) and line or
// paragraph separators are dropped, invalid UTF-8 is replaced, and the
// result is cut to maxShownError bytes. An empty result is "-".
func sanitize(s string) string {
	var b strings.Builder
	for _, c := range strings.ToValidUTF8(s, "?") {
		if unicode.IsControl(c) || unicode.Is(unicode.Cf, c) || c == '\u2028' || c == '\u2029' {
			continue
		}
		if b.Len()+utf8.RuneLen(c) > maxShownError {
			b.WriteString("…")
			break
		}
		b.WriteRune(c)
	}
	if b.Len() == 0 {
		return "-"
	}
	return b.String()
}

// deadlineCtx returns a context that ends at deadline, measured on the
// clock now comes from.
func deadlineCtx(ctx context.Context, deadline, now time.Time) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, deadline.Sub(now))
}
