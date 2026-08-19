package controller

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/T-Matrix/mmwx-guard/internal/model"
	"github.com/T-Matrix/mmwx-guard/internal/protocol"
	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
)

type agentConnection struct {
	conn    *websocket.Conn
	session *protocol.SecureSession
	writeMu sync.Mutex
}

type Hub struct {
	mu      sync.RWMutex
	agents  map[string]*agentConnection
	pending map[string]chan protocol.ApplyResult
}

func NewHub() *Hub {
	return &Hub{agents: make(map[string]*agentConnection), pending: make(map[string]chan protocol.ApplyResult)}
}

func (h *Hub) Register(id string, conn *websocket.Conn, session *protocol.SecureSession) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if old := h.agents[id]; old != nil {
		_ = old.conn.Close(websocket.StatusPolicyViolation, "replaced by a newer connection")
	}
	h.agents[id] = &agentConnection{conn: conn, session: session}
}

func (h *Hub) Unregister(id string, conn *websocket.Conn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if current := h.agents[id]; current != nil && current.conn == conn {
		delete(h.agents, id)
	}
}

func (h *Hub) Online(id string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.agents[id] != nil
}

func (h *Hub) Secure(id string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	agent := h.agents[id]
	return agent != nil && agent.session != nil
}

func (h *Hub) Resolve(requestID string, result protocol.ApplyResult) {
	h.mu.RLock()
	ch := h.pending[requestID]
	h.mu.RUnlock()
	if ch != nil {
		select {
		case ch <- result:
		default:
		}
	}
}

func (h *Hub) ApplyPolicy(ctx context.Context, agentID string, policy model.Policy) (protocol.ApplyResult, error) {
	return h.request(ctx, agentID, protocol.TypeApplyPolicy, protocol.ApplyPolicy{Policy: policy})
}

func (h *Hub) UpdateAgent(ctx context.Context, agentID string, update protocol.AgentUpdate) (protocol.ApplyResult, error) {
	return h.request(ctx, agentID, protocol.TypeUpdateAgent, update)
}

func (h *Hub) RotateCredential(ctx context.Context, agentID, secret string) (protocol.ApplyResult, error) {
	return h.request(ctx, agentID, protocol.TypeRotateCredential, protocol.RotateCredential{Secret: secret})
}

func (h *Hub) Disconnect(agentID, reason string) {
	h.mu.RLock()
	agent := h.agents[agentID]
	h.mu.RUnlock()
	if agent != nil {
		_ = agent.conn.Close(websocket.StatusPolicyViolation, reason)
	}
}

func (h *Hub) request(ctx context.Context, agentID, messageType string, payload any) (protocol.ApplyResult, error) {
	requestID, err := randomToken(16)
	if err != nil {
		return protocol.ApplyResult{}, err
	}
	msg, err := protocol.NewMessage(messageType, requestID, payload)
	if err != nil {
		return protocol.ApplyResult{}, err
	}
	ch := make(chan protocol.ApplyResult, 1)
	h.mu.Lock()
	agent := h.agents[agentID]
	if agent == nil {
		h.mu.Unlock()
		return protocol.ApplyResult{}, errors.New("agent is offline")
	}
	h.pending[requestID] = ch
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		delete(h.pending, requestID)
		h.mu.Unlock()
	}()
	agent.writeMu.Lock()
	writeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	if agent.session != nil {
		var envelope protocol.SecureEnvelope
		envelope, err = agent.session.EncryptMessage(msg)
		if err == nil {
			err = wsjson.Write(writeCtx, agent.conn, envelope)
		}
	} else {
		err = wsjson.Write(writeCtx, agent.conn, msg)
	}
	cancel()
	agent.writeMu.Unlock()
	if err != nil {
		return protocol.ApplyResult{}, err
	}
	select {
	case <-ctx.Done():
		return protocol.ApplyResult{}, ctx.Err()
	case result := <-ch:
		return result, nil
	}
}
