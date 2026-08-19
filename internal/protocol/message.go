package protocol

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/T-Matrix/mmwx-guard/internal/model"
)

const (
	MaxMessageBytes          = 320 << 10
	MaxTelemetryPayloadBytes = 192 << 10
	MaxResultPayloadBytes    = 8 << 10

	TypeHello              = "hello"
	TypeHelloAck           = "hello_ack"
	TypeTelemetry          = "telemetry"
	TypeApplyPolicy        = "apply_policy"
	TypeApplyResult        = "apply_result"
	TypeUpdateAgent        = "update_agent"
	TypeUpdateResult       = "update_result"
	TypeRotateCredential   = "rotate_credential"
	TypeRotateResult       = "rotate_result"
	TypeControllerVerified = "controller_verified"
	TypeAddressReport      = "address_report"
	TypeRollback           = "rollback_policy"
	TypeSyncBans           = "sync_bans"
	TypePing               = "ping"
	TypePong               = "pong"
)

type Message struct {
	Type      string          `json:"type"`
	RequestID string          `json:"request_id,omitempty"`
	SentAt    string          `json:"sent_at"`
	Payload   json.RawMessage `json:"payload,omitempty"`
}

func NewMessage(kind, requestID string, payload any) (Message, error) {
	raw, err := json.Marshal(payload)
	if err != nil {
		return Message{}, err
	}
	return Message{Type: kind, RequestID: requestID, SentAt: time.Now().UTC().Format(time.RFC3339Nano), Payload: raw}, nil
}

func ValidateFresh(message Message, now time.Time, maxAge time.Duration) error {
	if strings.TrimSpace(message.Type) == "" {
		return errors.New("message type is required")
	}
	sentAt, err := time.Parse(time.RFC3339Nano, message.SentAt)
	if err != nil {
		return errors.New("message timestamp is invalid")
	}
	if sentAt.After(now.Add(30 * time.Second)) {
		return errors.New("message timestamp is in the future")
	}
	if now.Sub(sentAt) > maxAge {
		return errors.New("message is stale")
	}
	return nil
}

func ValidateCommand(message Message, now time.Time) error {
	if err := ValidateFresh(message, now, 2*time.Minute); err != nil {
		return err
	}
	if length := len(message.RequestID); length < 16 || length > 128 {
		return fmt.Errorf("request ID length %d is invalid", length)
	}
	return nil
}

func ValidateHello(hello Hello) error {
	if strings.TrimSpace(hello.MachineID) == "" || len(hello.MachineID) > 256 || len(hello.Name) > 256 || len(hello.OS) > 64 || len(hello.Arch) > 64 || len(hello.Version) > 128 {
		return errors.New("hello metadata is invalid")
	}
	secureFields := hello.Challenge != "" || hello.AgentEphemeralPublicKey != "" || hello.ControllerKeyFingerprint != ""
	if secureFields {
		if _, err := DecodeKey(hello.Challenge, 32); err != nil {
			return errors.New("hello challenge is invalid")
		}
		if _, err := DecodeKey(hello.AgentEphemeralPublicKey, 32); err != nil {
			return errors.New("hello ephemeral key is invalid")
		}
		if hello.ControllerKeyFingerprint != "" {
			fingerprint, err := hex.DecodeString(hello.ControllerKeyFingerprint)
			if err != nil || len(fingerprint) != 32 {
				return errors.New("hello controller fingerprint is invalid")
			}
		}
	}
	return nil
}

func ValidateResult(message Message, result ApplyResult) error {
	if err := ValidateCommand(message, time.Now()); err != nil {
		return err
	}
	if len(message.Payload) > MaxResultPayloadBytes || len(result.Message) > 2048 || result.Revision < 0 {
		return errors.New("agent result is invalid")
	}
	return nil
}

type Hello struct {
	Name                     string `json:"name"`
	MachineID                string `json:"machine_id"`
	OS                       string `json:"os"`
	Arch                     string `json:"arch"`
	Version                  string `json:"version"`
	Challenge                string `json:"challenge,omitempty"`
	AgentEphemeralPublicKey  string `json:"agent_ephemeral_public_key,omitempty"`
	ControllerKeyFingerprint string `json:"controller_key_fingerprint,omitempty"`
}

type HelloAck struct {
	Version                      string `json:"version"`
	Secure                       bool   `json:"secure"`
	ControllerPublicKey          string `json:"controller_public_key,omitempty"`
	ControllerEphemeralPublicKey string `json:"controller_ephemeral_public_key,omitempty"`
	Signature                    string `json:"signature,omitempty"`
}

type HTTPSOpenResponse struct {
	SessionID string  `json:"session_id"`
	Message   Message `json:"message"`
}

type HTTPSExchange struct {
	SessionID string          `json:"session_id"`
	Envelope  *SecureEnvelope `json:"envelope,omitempty"`
}

type ApplyPolicy struct {
	Policy model.Policy `json:"policy"`
}

type ApplyResult struct {
	Success  bool   `json:"success"`
	Message  string `json:"message"`
	Revision int64  `json:"revision"`
}

type AgentUpdate struct {
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
	Size    int64  `json:"size"`
}

type RotateCredential struct {
	Secret string `json:"secret"`
}

type SyncBans struct {
	Bans []model.BanTarget `json:"bans"`
}

func ValidateSyncBans(value SyncBans, now time.Time) error {
	if len(value.Bans) > 2048 {
		return errors.New("too many IP bans")
	}
	seen := make(map[netip.Addr]bool, len(value.Bans))
	for _, ban := range value.Bans {
		address, err := netip.ParseAddr(strings.TrimSpace(ban.Address))
		if err != nil || !address.IsValid() || address.IsUnspecified() || address.IsLoopback() || address.IsMulticast() || address.IsLinkLocalUnicast() {
			return errors.New("IP ban contains an invalid address")
		}
		address = address.Unmap()
		if seen[address] {
			return errors.New("IP ban list contains a duplicate address")
		}
		seen[address] = true
		if ban.ExpiresAt != "" {
			expires, parseErr := time.Parse(time.RFC3339Nano, ban.ExpiresAt)
			if parseErr != nil || !expires.After(now) || expires.After(now.Add(366*24*time.Hour)) {
				return errors.New("IP ban expiry is invalid")
			}
		}
	}
	return nil
}

type ControllerVerified struct {
	Fingerprint string `json:"fingerprint"`
}

type AddressReport struct {
	IPv4 string `json:"ipv4,omitempty"`
	IPv6 string `json:"ipv6,omitempty"`
}

func ValidateAddressReport(report AddressReport) error {
	if report.IPv4 == "" && report.IPv6 == "" {
		return errors.New("address report is empty")
	}
	if report.IPv4 != "" {
		address, err := netip.ParseAddr(report.IPv4)
		if err != nil || !address.Is4() || !publicAddress(address) {
			return errors.New("address report contains an invalid public IPv4 address")
		}
	}
	if report.IPv6 != "" {
		address, err := netip.ParseAddr(report.IPv6)
		if err != nil || address.Is4() || !publicAddress(address) {
			return errors.New("address report contains an invalid public IPv6 address")
		}
	}
	return nil
}

func publicAddress(address netip.Addr) bool {
	return address.IsGlobalUnicast() && !address.IsPrivate() && !address.IsLoopback() && !address.IsLinkLocalUnicast()
}
