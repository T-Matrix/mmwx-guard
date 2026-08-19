package protocol

import (
	"encoding/json"
	"time"

	"github.com/T-Matrix/mmwx-guard/internal/model"
)

const (
	TypeHello        = "hello"
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
