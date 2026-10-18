package protect

// Choice is the protector picked for a new state file, and why
// (AGENT-PLAN §2 AG3: the platform protector where there is one, else
// the passphrase protector). `status` shows Reason, and Notice when the
// choice is not bound to the computer.
type Choice struct {
	Protector    string // TPMName, DPAPIName or PassphraseName
	Reason       string // plain text for the operator
	MachineBound bool
}

// Notice is the operator notice for a protector that is not bound to
// the computer (AGENT-PLAN §11), or "".
func (c Choice) Notice() string {
	if c.MachineBound {
		return ""
	}
	return NotMachineBound
}

// ChooseOptions are the operator's choices for ChooseProtector.
type ChooseOptions struct {
	// AllowPassphraseFallback chooses the passphrase protector when a
	// platform protector is present but does not work, instead of
	// returning the error (the operator asked for a passphrase).
	AllowPassphraseFallback bool
}
