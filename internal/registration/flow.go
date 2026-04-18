package registration

import (
	"fmt"
	"time"
)

type State int

const (
	StateIdle State = iota
	StateResolvingInvite
	StateConnectingNATS
	StateStoringCredentials
	StateWaitingApproval
	StateKeyExchange
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
	case StateStoringCredentials:
		return "storing_credentials"
	case StateWaitingApproval:
		return "waiting_approval"
	case StateKeyExchange:
		return "key_exchange"
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

// FlowConfig holds parameters for a registration flow.
type FlowConfig struct {
	InviteCode string
	AgentType  string
	Timeout    time.Duration
	ConfigDir  string
}

// RegistrationFlow manages the agent registration state machine.
//
// The previous implementation resolved invite codes via https://vett.id/{code},
// a domain that was never registered. That whole flow has been removed pending
// a redesign along the lines of vettid-dev/docs/DESKTOP-CONNECTION-FLOW.md
// (two-stage NATS pairing with owner-approval step).
type RegistrationFlow struct {
	state State
	cfg   FlowConfig
	err   error
}

// NewFlow creates a new registration flow from the given config.
func NewFlow(cfg FlowConfig) *RegistrationFlow {
	return &RegistrationFlow{
		state: StateIdle,
		cfg:   cfg,
	}
}

func (f *RegistrationFlow) State() State { return f.state }
func (f *RegistrationFlow) Err() error   { return f.err }

// Run is not yet implemented. The previous HTTP-broker pairing flow has been
// removed; the new NATS-based flow is pending design.
func (f *RegistrationFlow) Run() error {
	f.state = StateFailed
	f.err = fmt.Errorf("agent pairing not yet implemented — pending redesign (see vettid-dev/docs/DESKTOP-CONNECTION-FLOW.md for the parallel desktop design)")
	return f.err
}
