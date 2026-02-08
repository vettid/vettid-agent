package registration

type State int

const (
	StateIdle State = iota
	StateResolvingShortlink
	StateConnectingNATS
	StateSendingRequest
	StateWaitingApproval
	StateApproved
	StateDenied
	StateFailed
)

func (s State) String() string {
	switch s {
	case StateIdle:
		return "idle"
	case StateResolvingShortlink:
		return "resolving_shortlink"
	case StateConnectingNATS:
		return "connecting_nats"
	case StateSendingRequest:
		return "sending_request"
	case StateWaitingApproval:
		return "waiting_approval"
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

type RegistrationFlow struct {
	state        State
	shortlink    string
	invitationID string
	err          error
}

func NewFlow(shortlink string) *RegistrationFlow {
	return &RegistrationFlow{
		state:     StateIdle,
		shortlink: shortlink,
	}
}

func (f *RegistrationFlow) State() State { return f.state }
func (f *RegistrationFlow) Err() error   { return f.err }
