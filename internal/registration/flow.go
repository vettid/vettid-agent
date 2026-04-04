package registration

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/nats-io/nats.go"
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
	Shortlink string
	AgentType string
	Timeout   time.Duration
	ConfigDir string
}

// RegistrationFlow manages the full agent registration state machine.
// Uses the same P2P connection pattern as mobile apps and the desktop client:
// resolve invite → connect with JWT+seed → store-credentials → key exchange → save.
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

func (f *RegistrationFlow) State() State { return f.state }
func (f *RegistrationFlow) Err() error   { return f.err }

// Run executes the full registration flow using the P2P connection pattern.
//
// Phases:
// 1. Resolve invite code → get NATS JWT+seed credentials + connection info
// 2. Connect to NATS with JWT+seed (same as mobile peer connections)
// 3. Publish connection.store-credentials with agent metadata as peer_profile
// 4. Wait for vault to accept and phone user to approve
// 5. Receive key exchange with vault's X25519 public key
// 6. Compute shared secret, derive connection key, save encrypted credentials
func (f *RegistrationFlow) Run() error {
	// Phase 1: Resolve invite code
	f.state = StateResolvingInvite
	fmt.Println("Resolving invite code...")

	invitation, err := ResolveInviteCode(f.shortlink)
	if err != nil {
		f.state = StateFailed
		f.err = fmt.Errorf("resolve invite: %w", err)
		return f.err
	}

	log.Info().
		Str("connection_id", invitation.ConnectionID).
		Str("owner_space", invitation.OwnerSpace).
		Msg("Invite resolved")

	// Phase 2: Connect to NATS with JWT+seed credentials
	f.state = StateConnectingNATS
	fmt.Println("Connecting to MessageSpace...")

	client, err := vettidnats.NewClient(&vettidnats.ClientConfig{
		URL:       invitation.NATSEndpoint,
		JWT:       invitation.JWT,
		Seed:      invitation.Seed,
		OwnerGUID: invitation.OwnerSpace,
	})
	if err != nil {
		f.state = StateFailed
		f.err = fmt.Errorf("connect to NATS: %w", err)
		return f.err
	}
	defer client.Close()

	log.Info().Msg("Connected to MessageSpace with JWT credentials")

	// Phase 3: Generate keypair and publish store-credentials
	f.state = StateStoringCredentials
	fmt.Println("Sending connection request...")

	// Generate agent X25519 keypair
	agentKP, err := crypto.GenerateX25519KeyPair()
	if err != nil {
		f.state = StateFailed
		f.err = fmt.Errorf("generate agent keypair: %w", err)
		return f.err
	}
	var agentPrivKey [crypto.KeySize]byte
	copy(agentPrivKey[:], agentKP.PrivateKey[:])

	// Collect machine/agent metadata
	hostname, _ := os.Hostname()
	binaryFP, err := fingerprint.BinaryFingerprint()
	if err != nil {
		binaryFP = "unavailable"
	}
	attrs, _ := fingerprint.CollectMachineAttributes()
	machineFP := fingerprint.ComputeMachineFingerprintHex(attrs)

	// Build store-credentials payload (same format as mobile/desktop)
	requestID := hex.EncodeToString(crypto.RandomBytes(16))
	natsCredsString := fmt.Sprintf(
		"-----BEGIN NATS USER JWT-----\n%s\n------END NATS USER JWT------\n\n-----BEGIN USER NKEY SEED-----\n%s\n------END USER NKEY SEED------",
		invitation.JWT, invitation.Seed,
	)

	storePayload := map[string]interface{}{
		"connection_id":        invitation.ConnectionID,
		"peer_guid":            fmt.Sprintf("agent-%s", hex.EncodeToString(crypto.RandomBytes(8))),
		"label":                hostname,
		"nats_credentials":     natsCredsString,
		"peer_owner_space_id":  invitation.OwnerSpace,
		"peer_message_space_id": invitation.MessageSpace,
		"peer_profile": map[string]interface{}{
			"_system_first_name": hostname,
			"_system_last_name":  "Agent",
			"agent_type":         f.agentType,
			"hostname":           hostname,
			"platform":           fingerprint.Platform(),
			"binary_fingerprint":  binaryFP,
			"machine_fingerprint": machineFP,
			"ip_address":          detectLocalIP(),
		},
		"e2e_public_key":  hex.EncodeToString(agentKP.PublicKey[:]),
		"connection_type": "agent",
	}

	vaultMessage := map[string]interface{}{
		"id":        requestID,
		"type":      "connection.store-credentials",
		"payload":   storePayload,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}

	messageBytes, err := json.Marshal(vaultMessage)
	if err != nil {
		crypto.ZeroBytes(agentPrivKey[:])
		f.state = StateFailed
		f.err = fmt.Errorf("marshal store-credentials: %w", err)
		return f.err
	}

	// Publish to MessageSpace (not OwnerSpace — agents use MessageSpace like peers)
	storeSubject := fmt.Sprintf("MessageSpace.%s.forOwner.connection.store-credentials", invitation.OwnerSpace)
	if err := client.PublishTo(storeSubject, messageBytes); err != nil {
		crypto.ZeroBytes(agentPrivKey[:])
		f.state = StateFailed
		f.err = fmt.Errorf("publish store-credentials: %w", err)
		return f.err
	}

	log.Info().Msg("Store-credentials request sent, waiting for approval...")

	// Phase 4: Wait for store-credentials response
	f.state = StateWaitingApproval
	fmt.Printf("Waiting for owner approval (timeout: %s)...\n", f.timeout)

	// Subscribe to store-credentials response
	storeResponseSubject := fmt.Sprintf("MessageSpace.%s.forOwner.connection.store-credentials.response", invitation.OwnerSpace)
	storeResponseCh := make(chan []byte, 1)
	storeSub, err := client.SubscribeTo(storeResponseSubject, func(msg *nats.Msg) {
		select {
		case storeResponseCh <- msg.Data:
		default:
		}
	})
	if err != nil {
		crypto.ZeroBytes(agentPrivKey[:])
		f.state = StateFailed
		f.err = fmt.Errorf("subscribe to store response: %w", err)
		return f.err
	}
	defer storeSub.Unsubscribe()

	// Subscribe to connection events (key exchange, activation)
	connEventSubject := fmt.Sprintf("MessageSpace.%s.forOwner.connection.>", invitation.OwnerSpace)
	connEventCh := make(chan []byte, 10)
	connSub, err := client.SubscribeTo(connEventSubject, func(msg *nats.Msg) {
		select {
		case connEventCh <- msg.Data:
		default:
		}
	})
	if err != nil {
		crypto.ZeroBytes(agentPrivKey[:])
		f.state = StateFailed
		f.err = fmt.Errorf("subscribe to connection events: %w", err)
		return f.err
	}
	defer connSub.Unsubscribe()

	// Wait for store-credentials response
	timer := time.NewTimer(30 * time.Second)
	select {
	case <-timer.C:
		crypto.ZeroBytes(agentPrivKey[:])
		f.state = StateFailed
		f.err = fmt.Errorf("timed out waiting for store-credentials response")
		return f.err
	case data := <-storeResponseCh:
		timer.Stop()
		var result map[string]interface{}
		if err := json.Unmarshal(data, &result); err != nil {
			crypto.ZeroBytes(agentPrivKey[:])
			f.state = StateFailed
			f.err = fmt.Errorf("parse store response: %w", err)
			return f.err
		}
		success, _ := result["success"].(bool)
		if !success {
			errMsg, _ := result["error"].(string)
			if errMsg == "" {
				errMsg = "store-credentials rejected"
			}
			crypto.ZeroBytes(agentPrivKey[:])
			f.state = StateDenied
			f.err = fmt.Errorf("connection denied: %s", errMsg)
			return f.err
		}
		log.Info().Msg("Store-credentials accepted")
	}

	// Phase 5: Wait for key exchange message
	f.state = StateKeyExchange
	fmt.Println("Waiting for key exchange...")

	keyExchangeTimer := time.NewTimer(f.timeout)
	var vaultPublicKeyHex string

	for {
		select {
		case <-keyExchangeTimer.C:
			crypto.ZeroBytes(agentPrivKey[:])
			f.state = StateFailed
			f.err = fmt.Errorf("timed out waiting for key exchange after %s", f.timeout)
			return f.err

		case data := <-connEventCh:
			var event map[string]interface{}
			if err := json.Unmarshal(data, &event); err != nil {
				continue
			}
			// Look for e2e_public_key in the event
			if pubKey, ok := event["e2e_public_key"].(string); ok && pubKey != "" {
				vaultPublicKeyHex = pubKey
				keyExchangeTimer.Stop()
				goto keyExchangeReceived
			}
		}
	}

keyExchangeReceived:
	f.state = StateApproved
	fmt.Println("\nConnection approved! Key exchange complete.")

	// Phase 6: Compute shared secret and save credentials
	vaultPubKeyBytes, err := hex.DecodeString(vaultPublicKeyHex)
	if err != nil || len(vaultPubKeyBytes) != crypto.KeySize {
		crypto.ZeroBytes(agentPrivKey[:])
		f.state = StateFailed
		f.err = fmt.Errorf("invalid vault public key in key exchange")
		return f.err
	}

	// X25519 ECDH shared secret
	sharedSecret, err := crypto.ComputeSharedSecret(agentPrivKey[:], vaultPubKeyBytes)
	if err != nil {
		crypto.ZeroBytes(agentPrivKey[:])
		f.state = StateFailed
		f.err = fmt.Errorf("compute shared secret: %w", err)
		return f.err
	}
	defer crypto.ZeroBytes(sharedSecret)

	// HKDF-SHA256 with connection_id as salt
	connectionKey, err := crypto.DeriveConnectionKey(sharedSecret, invitation.ConnectionID)
	if err != nil {
		crypto.ZeroBytes(agentPrivKey[:])
		f.state = StateFailed
		f.err = fmt.Errorf("derive connection key: %w", err)
		return f.err
	}
	defer crypto.ZeroBytes(connectionKey)

	// Prompt for passphrase
	passphrase, err := readPassphrase()
	if err != nil {
		crypto.ZeroBytes(agentPrivKey[:])
		f.state = StateFailed
		f.err = fmt.Errorf("read passphrase: %w", err)
		return f.err
	}
	defer crypto.ZeroBytes(passphrase)

	// Derive platform key
	platformKey, err := fingerprint.DerivePlatformKey("")
	if err != nil {
		crypto.ZeroBytes(agentPrivKey[:])
		f.state = StateFailed
		f.err = fmt.Errorf("derive platform key: %w", err)
		return f.err
	}
	defer crypto.ZeroBytes(platformKey)

	// Build and save credentials
	connKeyCopy := make([]byte, len(connectionKey))
	copy(connKeyCopy, connectionKey)

	creds := &credential.ConnectionCredentials{
		ConnectionID:    invitation.ConnectionID,
		ConnectionKey:   connKeyCopy,
		KeyID:           hex.EncodeToString(agentKP.PublicKey[:]),
		AgentPrivateKey: agentPrivKey[:],
		AgentPublicKey:  agentKP.PublicKey[:],
		VaultPublicKey:  vaultPubKeyBytes,
		JWT:             invitation.JWT,
		Seed:            invitation.Seed,
		MessageSpaceURL: invitation.NATSEndpoint,
		OwnerGUID:       invitation.OwnerSpace,
		OwnerName:       invitation.Label,
		Scope:           []string{}, // Set by vault after contract review
		ApprovalMode:    "always_ask",
	}
	defer creds.Zero()

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
