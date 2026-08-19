package protocol

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/T-Matrix/mmwx-guard/internal/model"
)

const (
	MaxMessageBytes          = 256 << 10
	MaxTelemetryPayloadBytes = 192 << 10
	MaxResultPayloadBytes    = 8 << 10

	TypeHello        = "hello"
	TypeHelloAck     = "hello_ack"
	TypeTelemetry    = "telemetry"
	TypeApplyPolicy  = "apply_policy"
	TypeApplyResult  = "apply_result"
	TypeUpdateAgent  = "update_agent"
	TypeUpdateResult = "update_result"
	TypeRollback     = "rollback_policy"
	TypePing         = "ping"
	TypePong         = "pong"
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
	Name      string `json:"name"`
	MachineID string `json:"machine_id"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
	Version   string `json:"version"`
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
