package registration

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/term"

	"github.com/vettid/vettid-agent/internal/credential"
	"github.com/vettid/vettid-agent/internal/crypto"
	"github.com/vettid/vettid-agent/internal/fingerprint"
	vettidnats "github.com/vettid/vettid-agent/internal/nats"
)

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

// FlowConfig holds parameters for a registration flow.
type FlowConfig struct {
	Shortlink string
	AgentType string
	Timeout   time.Duration
	ConfigDir string
}

// RegistrationFlow manages the full agent registration state machine.
type RegistrationFlow struct {
	state     State
	shortlink string
	agentType string
	timeout   time.Duration
	configDir string
	err       error
}

// NewFlow creates a new registration flow from the given config.
func NewFlow(cfg FlowConfig) *RegistrationFlow {
	return &RegistrationFlow{
		state:     StateIdle,
		shortlink: cfg.Shortlink,
		agentType: cfg.AgentType,
		timeout:   cfg.Timeout,
		configDir: cfg.ConfigDir,
	}
}

// State returns the current state of the registration flow.
func (f *RegistrationFlow) State() State { return f.state }

// Err returns the error that caused the flow to fail, if any.
func (f *RegistrationFlow) Err() error { return f.err }

// Run executes the full registration flow, blocking until approval, denial, or timeout.
func (f *RegistrationFlow) Run() error {
	// Phase 1: Resolve shortlink
	f.state = StateResolvingShortlink
	fmt.Println("Resolving shortlink...")

	payload, err := ResolveShortlink(f.shortlink)
	if err != nil {
		f.state = StateFailed
		f.err = fmt.Errorf("resolve shortlink: %w", err)
		return f.err
	}

	// Decode vault public key from hex
	vaultPubKey, err := hex.DecodeString(payload.VaultPublicKey)
	if err != nil {
		f.state = StateFailed
		f.err = fmt.Errorf("decode vault public key: %w", err)
		return f.err
	}
	if len(vaultPubKey) != crypto.KeySize {
		f.state = StateFailed
		f.err = fmt.Errorf("vault public key must be %d bytes, got %d", crypto.KeySize, len(vaultPubKey))
		return f.err
	}

	log.Info().
		Str("invitation_id", payload.InvitationID).
		Str("messagespace", payload.MessageSpaceURI).
		Msg("Shortlink resolved")

	// Phase 2: Connect to NATS
	f.state = StateConnectingNATS
	fmt.Println("Connecting to MessageSpace...")

	client, err := vettidnats.NewClient(&vettidnats.ClientConfig{
		URL:       payload.MessageSpaceURI,
		Token:     payload.InviteToken,
		OwnerGUID: payload.OwnerGUID,
	})
	if err != nil {
		f.state = StateFailed
		f.err = fmt.Errorf("connect to NATS: %w", err)
		return f.err
	}
	defer client.Close()

	// Subscribe to invitation-specific response topic
	resultCh := make(chan *vettidnats.Envelope, 1)
	sub, err := client.SubscribeRegistration(payload.InvitationID, func(env *vettidnats.Envelope) {
		select {
		case resultCh <- env:
		default:
			log.Warn().Msg("Duplicate registration response received, ignoring")
		}
	})
	if err != nil {
		f.state = StateFailed
		f.err = fmt.Errorf("subscribe to registration responses: %w", err)
		return f.err
	}
	defer sub.Unsubscribe()

	log.Info().Msg("Connected to MessageSpace")

	// Phase 3: Build and send registration request
	f.state = StateSendingRequest
	fmt.Println("Sending registration request...")

	// Generate agent X25519 keypair
	agentKP, err := crypto.GenerateX25519KeyPair()
	if err != nil {
		f.state = StateFailed
		f.err = fmt.Errorf("generate agent keypair: %w", err)
		return f.err
	}
	// SECURITY: zero private key after we're done with it (unless approved)
	var agentPrivKey [crypto.KeySize]byte
	copy(agentPrivKey[:], agentKP.PrivateKey[:])

	// Collect machine attributes
	attrs, err := fingerprint.CollectMachineAttributes()
	if err != nil {
		crypto.ZeroBytes(agentPrivKey[:])
		f.state = StateFailed
		f.err = fmt.Errorf("collect machine attributes: %w", err)
		return f.err
	}

	machineFingerprint := fingerprint.ComputeMachineFingerprintHex(attrs)

	binaryFP, err := fingerprint.BinaryFingerprint()
	if err != nil {
		binaryFP = "unavailable"
		log.Warn().Err(err).Msg("Could not compute binary fingerprint")
	}

	hostname, _ := os.Hostname()
	ipAddr := detectLocalIP()

	connReq := &vettidnats.ConnectionRequest{
		InvitationID:   payload.InvitationID,
		AgentPublicKey: agentKP.PublicKey[:],
		Registration: vettidnats.AgentRegistration{
			AgentType:          f.agentType,
			IPAddress:          ipAddr,
			Hostname:           hostname,
			Platform:           fingerprint.Platform(),
			BinaryFingerprint:  binaryFP,
			MachineFingerprint: machineFingerprint,
		},
		Timestamp: time.Now().UTC(),
	}

	// ECIES-encrypt and publish
	if err := client.PublishRegistration(connReq, vaultPubKey); err != nil {
		crypto.ZeroBytes(agentPrivKey[:])
		f.state = StateFailed
		f.err = fmt.Errorf("publish registration request: %w", err)
		return f.err
	}

	log.Info().Msg("Registration request sent, waiting for owner approval...")

	// Phase 4: Wait for approval
	f.state = StateWaitingApproval
	fmt.Printf("Waiting for owner approval (timeout: %s)...\n", f.timeout)

	timer := time.NewTimer(f.timeout)
	defer timer.Stop()

	for {
		select {
		case <-timer.C:
			crypto.ZeroBytes(agentPrivKey[:])
			f.state = StateFailed
			f.err = fmt.Errorf("timed out waiting for owner approval after %s", f.timeout)
			return f.err

		case env := <-resultCh:
			switch env.Type {
			case vettidnats.MsgAgentConnectionApproved:
				// Phase 5: Save credentials
				err := f.handleApproval(env, agentPrivKey[:], agentKP.PublicKey[:], vaultPubKey, payload)
				crypto.ZeroBytes(agentPrivKey[:])
				return err

			case vettidnats.MsgAgentConnectionDenied:
				crypto.ZeroBytes(agentPrivKey[:])
				var denial vettidnats.ConnectionDenial
				if jsonErr := json.Unmarshal(env.Payload, &denial); jsonErr != nil {
					f.state = StateDenied
					f.err = fmt.Errorf("connection denied (could not parse reason)")
					return f.err
				}
				f.state = StateDenied
				f.err = fmt.Errorf("connection denied by owner: %s", denial.Reason)
				return f.err

			default:
				log.Warn().Str("type", string(env.Type)).Msg("Unexpected message type during registration, ignoring")
			}
		}
	}
}

// handleApproval processes an approval envelope: derives connection key via X25519+HKDF,
// decrypts the approval payload, prompts for passphrase, and saves credentials.
func (f *RegistrationFlow) handleApproval(env *vettidnats.Envelope, agentPrivKey, agentPubKey, vaultPubKey []byte, payload *ShortlinkPayload) error {
	f.state = StateApproved
	fmt.Println("\nConnection approved!")

	// SECURITY: Derive connection key from X25519 shared secret via HKDF.
	// Both sides independently compute the same key from their ECDH shared secret.
	sharedSecret, err := crypto.ComputeSharedSecret(agentPrivKey, vaultPubKey)
	if err != nil {
		f.state = StateFailed
		f.err = fmt.Errorf("compute shared secret: %w", err)
		return f.err
	}
	defer crypto.ZeroBytes(sharedSecret)

	connectionKey, err := crypto.DeriveConnectionKey(sharedSecret)
	if err != nil {
		f.state = StateFailed
		f.err = fmt.Errorf("derive connection key: %w", err)
		return f.err
	}
	defer crypto.ZeroBytes(connectionKey)

	// SECURITY: Decrypt approval payload with the derived connection key (XChaCha20-Poly1305).
	// The vault encrypted this with the same connection key derived from the same shared secret.
	decrypted, err := crypto.Decrypt(connectionKey, env.Payload, nil)
	if err != nil {
		f.state = StateFailed
		f.err = fmt.Errorf("decrypt approval: %w", err)
		return f.err
	}
	defer crypto.ZeroBytes(decrypted)

	var approval vettidnats.ConnectionApproval
	if err := json.Unmarshal(decrypted, &approval); err != nil {
		f.state = StateFailed
		f.err = fmt.Errorf("parse approval: %w", err)
		return f.err
	}

	log.Info().
		Str("connection_id", approval.ConnectionID).
		Str("key_id", approval.KeyID).
		Str("approval_mode", approval.Contract.ApprovalMode).
		Msg("Connection details received")

	// Prompt for passphrase
	passphrase, err := readPassphrase()
	if err != nil {
		f.state = StateFailed
		f.err = fmt.Errorf("read passphrase: %w", err)
		return f.err
	}
	defer crypto.ZeroBytes(passphrase)

	// Derive platform key
	platformKey, err := fingerprint.DerivePlatformKey("")
	if err != nil {
		f.state = StateFailed
		f.err = fmt.Errorf("derive platform key: %w", err)
		return f.err
	}
	defer crypto.ZeroBytes(platformKey)

	// SECURITY: Copy connection key for credentials — the deferred ZeroBytes above
	// will wipe the original, but credentials need a live copy for Save.
	connKeyCopy := make([]byte, len(connectionKey))
	copy(connKeyCopy, connectionKey)

	// Build credentials
	creds := &credential.ConnectionCredentials{
		ConnectionID:      approval.ConnectionID,
		ConnectionKey:     connKeyCopy,
		KeyID:             approval.KeyID,
		AgentPrivateKey:   agentPrivKey,
		AgentPublicKey:    agentPubKey,
		VaultPublicKey:    vaultPubKey,
		MessageSpaceToken: payload.InviteToken,
		MessageSpaceURL:   payload.MessageSpaceURI,
		OwnerGUID:         payload.OwnerGUID,
		Scope:             approval.Contract.Scope,
		ApprovalMode:      approval.Contract.ApprovalMode,
	}
	defer creds.Zero()

	// Save encrypted credentials
	if err := credential.Save(f.configDir, creds, passphrase, platformKey); err != nil {
		f.state = StateFailed
		f.err = fmt.Errorf("save credentials: %w", err)
		return f.err
	}

	fmt.Printf("\nCredentials saved to %s/connection.enc\n", f.configDir)
	return nil
}

// readPassphrase prompts for a passphrase with confirmation, reading from stdin with echo disabled.
func readPassphrase() ([]byte, error) {
	fmt.Print("\nEnter encryption passphrase: ")
	pass1, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		return nil, fmt.Errorf("read passphrase: %w", err)
	}

	if len(pass1) == 0 {
		return nil, fmt.Errorf("passphrase cannot be empty")
	}

	fmt.Print("Confirm passphrase: ")
	pass2, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		crypto.ZeroBytes(pass1)
		return nil, fmt.Errorf("read passphrase confirmation: %w", err)
	}

	if !crypto.TimingSafeEqual(pass1, pass2) {
		crypto.ZeroBytes(pass1)
		crypto.ZeroBytes(pass2)
		return nil, fmt.Errorf("passphrases do not match")
	}

	crypto.ZeroBytes(pass2)
	return pass1, nil
}

// detectLocalIP returns the first non-loopback IPv4 address, or "unknown" if unavailable.
func detectLocalIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "unknown"
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() && ipnet.IP.To4() != nil {
			return ipnet.IP.String()
		}
	}
	return "unknown"
}
