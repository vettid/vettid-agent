package pairing

// The operator texts of AGENT-PLAN §11 used by `vettid-agent pair`. They
// are written to the operator's terminal (standard error), never to
// standard output.
const (
	// TextStart is shown before the code is asked for.
	TextStart = "Paste the pairing code from Devices & agents on your phone. It expires 10 minutes after the phone showed it."
	// textSAS is the SAS line; %s is the code as "123 456".
	textSAS = "Check that your phone shows the same code: %s. Approve on your phone only if it matches."
	// TextWaiting is shown while waiting for the approval.
	TextWaiting = "Waiting for you to approve on your phone…"
	// TextPaired is shown when the vault's device.paired arrived and the
	// state was saved.
	TextPaired = "Paired with your vault. Your phone decides what this agent may do."
	// TextRejected is shown on device.pair.rejected (VAULT-MESSAGING §6.7).
	TextRejected = "Rejected on your phone."
	// TextExpired is shown when the 10 minutes after hs.init end, or the
	// code itself has expired.
	TextExpired = "The pairing timed out. Start again from your phone."
)

// Texts of this command that AGENT-PLAN §11 does not draft (chosen; not
// in the spec).
const (
	// textContacting is shown before the relay is first contacted.
	textContacting = "Contacting your vault…"
	// textResume is shown when an interrupted wait is resumed; %s is the
	// time the wait ends.
	textResume = "Resuming the pairing started earlier on this computer; the wait ends at %s. Approve on your phone only if it shows the code this computer showed when the pairing started."
	// textInterrupted is shown when the operator interrupts the wait
	// after the SAS was shown; %s is the time the wait ends.
	textInterrupted = "Pairing interrupted. To keep waiting, run `vettid-agent pair` again (without a code) before %s; to start over, get a new code from your phone."
	// textInterruptedEarly is shown when the operator interrupts before
	// the SAS was shown: nothing is kept.
	textInterruptedEarly = "Pairing interrupted before a code to compare was shown; nothing was kept. Start again from your phone."
	// textDiscarded is shown when an unfinished pairing is discarded.
	textDiscarded = "An unfinished pairing on this computer was discarded; its keys are deleted."
	// textReplaced is shown when --restart replaces a completed pairing.
	textReplaced = "This replaces the existing pairing; the old one stays listed on your phone until you remove it there."
)
