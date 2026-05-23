// Package registration implements the agent pairing flow.
//
// The user-facing entry points are ResolveInvite (stage 1) and
// CompletePairing (stage 2) — see pairing.go and pairing_stage2.go for
// implementation, AGENT-PAIRING-FLOW.md for the protocol.
//
// The State enum below is exported for log/UI use (e.g. progress
// indicators on the local API) — the registration logic itself isn't a
// state machine; it's a straight-line two-stage call.
package registration

// State labels the high-level steps of a pairing run. Mostly useful for
// human-facing progress text.
type State int

const (
	StateIdle State = iota
	StateResolvingInvite
	StateConnectingNATS
	StateWaitingApproval
	StateKeyExchange
	StateStoringCredentials
	StateApproved
	StateDenied
	StateFailed
)

func (s State) String() string {
	switch s {
	case StateIdle:
		return "idle"
	case StateResolvingInvite:
		return "resolving_invite"
	case StateConnectingNATS:
		return "connecting_nats"
	case StateWaitingApproval:
		return "waiting_approval"
	case StateKeyExchange:
		return "key_exchange"
	case StateStoringCredentials:
		return "storing_credentials"
	case StateApproved:
		return "approved"
	case StateDenied:
		return "denied"
	case StateFailed:
		return "failed"
	default:
		return "unknown"
	}
}
