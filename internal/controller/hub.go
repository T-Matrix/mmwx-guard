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

var errHTTPSExchangeBusy = errors.New("HTTPS exchange already in progress")

type agentConnection struct {
	conn           *websocket.Conn
	session        *protocol.SecureSession
	httpsSessionID string
	lastSeen       time.Time
	notify         chan struct{}
	done           chan struct{}
	exchange       chan struct{}
	doneOnce       sync.Once
	writeMu        sync.Mutex
}

type Hub struct {
	mu              sync.RWMutex
	agents          map[string]*agentConnection
	pending         map[string]chan protocol.ApplyResult
	pendingAgents   map[string]string
	httpsCommands   map[string]map[string]protocol.Message
	httpsCommandIDs map[string][]string
}

func NewHub() *Hub {
	return &Hub{
		agents: make(map[string]*agentConnection), pending: make(map[string]chan protocol.ApplyResult),
		pendingAgents: make(map[string]string), httpsCommands: make(map[string]map[string]protocol.Message),
		httpsCommandIDs: make(map[string][]string),
	}
}

func (h *Hub) Register(id string, conn *websocket.Conn, session *protocol.SecureSession) {
	h.mu.Lock()
	old := h.agents[id]
	registered := &agentConnection{conn: conn, session: session, lastSeen: time.Now(), done: make(chan struct{})}
	h.agents[id] = registered
	h.mu.Unlock()
	closeAgentConnection(old, "replaced by a newer connection")
	go h.flushHTTPSCommandsToWebSocket(id, registered)
}

func (h *Hub) RegisterHTTPS(id, sessionID string, session *protocol.SecureSession) {
	h.mu.Lock()
	old := h.agents[id]
	h.agents[id] = &agentConnection{
		session: session, httpsSessionID: sessionID, lastSeen: time.Now(),
		notify: make(chan struct{}, 1), done: make(chan struct{}), exchange: make(chan struct{}, 1),
	}
	h.mu.Unlock()
	closeAgentConnection(old, "replaced by HTTPS fallback")
}

func (h *Hub) Unregister(id string, conn *websocket.Conn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if current := h.agents[id]; current != nil && current.conn == conn {
		delete(h.agents, id)
	}
}

func (h *Hub) UnregisterHTTPS(id, sessionID string) bool {
	h.mu.Lock()
	current := h.agents[id]
	if current == nil || current.httpsSessionID != sessionID {
		h.mu.Unlock()
		return false
	}
	delete(h.agents, id)
	h.mu.Unlock()
	closeAgentConnection(current, "HTTPS fallback expired")
	return true
}

func (h *Hub) Online(id string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	agent := h.agents[id]
	return agent != nil && (agent.httpsSessionID == "" || time.Since(agent.lastSeen) <= 45*time.Second)
}

func (h *Hub) Secure(id string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	agent := h.agents[id]
	return agent != nil && agent.session != nil
}

func (h *Hub) Resolve(requestID string, result protocol.ApplyResult) {
	h.mu.Lock()
	ch := h.pending[requestID]
	agentID := h.pendingAgents[requestID]
	h.removeHTTPSCommandLocked(agentID, requestID)
	h.mu.Unlock()
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

func (h *Hub) SyncBans(ctx context.Context, agentID string, bans []model.BanTarget) (protocol.ApplyResult, error) {
	return h.request(ctx, agentID, protocol.TypeSyncBans, protocol.SyncBans{Bans: bans})
}

func (h *Hub) Disconnect(agentID, reason string) {
	h.mu.Lock()
	agent := h.agents[agentID]
	if agent != nil {
		delete(h.agents, agentID)
	}
	h.mu.Unlock()
	closeAgentConnection(agent, reason)
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
	if agent == nil || (agent.httpsSessionID != "" && time.Since(agent.lastSeen) > 45*time.Second) {
		h.mu.Unlock()
		return protocol.ApplyResult{}, errors.New("agent is offline")
	}
	h.pending[requestID] = ch
	h.pendingAgents[requestID] = agentID
	if h.httpsCommands[agentID] == nil {
		h.httpsCommands[agentID] = make(map[string]protocol.Message)
	}
	h.httpsCommands[agentID][requestID] = msg
	h.httpsCommandIDs[agentID] = append(h.httpsCommandIDs[agentID], requestID)
	if agent.httpsSessionID != "" {
		signalAgent(agent)
	}
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		delete(h.pending, requestID)
		delete(h.pendingAgents, requestID)
		h.removeHTTPSCommandLocked(agentID, requestID)
		h.mu.Unlock()
	}()
	if agent.httpsSessionID == "" {
		if err := writeWebSocketMessage(ctx, agent, msg); err != nil {
			closeAgentConnection(agent, "WebSocket write failed; waiting for HTTPS fallback")
		}
	}
	select {
	case <-ctx.Done():
		return protocol.ApplyResult{}, ctx.Err()
	case result := <-ch:
		return result, nil
	}
}

func (h *Hub) DecryptHTTPS(agentID, sessionID string, envelope protocol.SecureEnvelope) (protocol.Message, error) {
	h.mu.Lock()
	agent := h.agents[agentID]
	if agent == nil || agent.httpsSessionID != sessionID || time.Since(agent.lastSeen) > 45*time.Second {
		h.mu.Unlock()
		return protocol.Message{}, errors.New("HTTPS session is invalid or expired")
	}
	agent.lastSeen = time.Now()
	h.mu.Unlock()
	return agent.session.DecryptMessage(envelope)
}

func (h *Hub) NextHTTPSEnvelope(ctx context.Context, agentID, sessionID string) (*protocol.SecureEnvelope, error) {
	if !h.TouchHTTPS(agentID, sessionID) {
		return nil, errors.New("HTTPS session is invalid or expired")
	}
	message, ok, err := h.nextHTTPSCommand(ctx, agentID, sessionID)
	if err != nil || !ok {
		return nil, err
	}
	h.mu.RLock()
	agent := h.agents[agentID]
	valid := agent != nil && agent.httpsSessionID == sessionID
	h.mu.RUnlock()
	if !valid {
		return nil, errors.New("HTTPS session was replaced")
	}
	envelope, err := agent.session.EncryptMessage(message)
	return &envelope, err
}

func (h *Hub) TouchHTTPS(agentID, sessionID string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	agent := h.agents[agentID]
	if agent == nil || agent.httpsSessionID != sessionID || time.Since(agent.lastSeen) > 45*time.Second {
		return false
	}
	agent.lastSeen = time.Now()
	return true
}

func (h *Hub) BeginHTTPSExchange(agentID, sessionID string) (func(), error) {
	h.mu.Lock()
	agent := h.agents[agentID]
	if agent == nil || agent.httpsSessionID != sessionID || time.Since(agent.lastSeen) > 45*time.Second {
		h.mu.Unlock()
		return nil, errors.New("HTTPS session is invalid or expired")
	}
	agent.lastSeen = time.Now()
	h.mu.Unlock()
	select {
	case agent.exchange <- struct{}{}:
		return func() { <-agent.exchange }, nil
	default:
		return nil, errHTTPSExchangeBusy
	}
}

func (h *Hub) HTTPSSessionActive(agentID, sessionID string, maxIdle time.Duration) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	agent := h.agents[agentID]
	return agent != nil && agent.httpsSessionID == sessionID && time.Since(agent.lastSeen) <= maxIdle
}

func (h *Hub) nextHTTPSCommand(ctx context.Context, agentID, sessionID string) (protocol.Message, bool, error) {
	for {
		h.mu.Lock()
		agent := h.agents[agentID]
		if agent == nil || agent.httpsSessionID != sessionID {
			h.mu.Unlock()
			return protocol.Message{}, false, errors.New("HTTPS session was replaced")
		}
		for _, requestID := range h.httpsCommandIDs[agentID] {
			if message, ok := h.httpsCommands[agentID][requestID]; ok {
				h.mu.Unlock()
				return message, true, nil
			}
		}
		notify, done := agent.notify, agent.done
		h.mu.Unlock()
		select {
		case <-ctx.Done():
			return protocol.Message{}, false, nil
		case <-notify:
		case <-done:
			return protocol.Message{}, false, errors.New("HTTPS session was replaced")
		}
	}
}

func (h *Hub) flushHTTPSCommandsToWebSocket(agentID string, agent *agentConnection) {
	h.mu.RLock()
	ids := append([]string(nil), h.httpsCommandIDs[agentID]...)
	h.mu.RUnlock()
	for _, requestID := range ids {
		h.mu.RLock()
		current := h.agents[agentID]
		message, ok := h.httpsCommands[agentID][requestID]
		h.mu.RUnlock()
		if current != agent || !ok {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err := writeWebSocketMessage(ctx, agent, message)
		cancel()
		if err != nil {
			return
		}
	}
}

func (h *Hub) removeHTTPSCommandLocked(agentID, requestID string) {
	if agentID == "" || h.httpsCommands[agentID] == nil {
		return
	}
	delete(h.httpsCommands[agentID], requestID)
	if len(h.httpsCommands[agentID]) == 0 {
		delete(h.httpsCommands, agentID)
		delete(h.httpsCommandIDs, agentID)
	}
}

func writeWebSocketMessage(ctx context.Context, agent *agentConnection, msg protocol.Message) error {
	agent.writeMu.Lock()
	defer agent.writeMu.Unlock()
	writeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if agent.session != nil {
		envelope, err := agent.session.EncryptMessage(msg)
		if err != nil {
			return err
		}
		return wsjson.Write(writeCtx, agent.conn, envelope)
	}
	return wsjson.Write(writeCtx, agent.conn, msg)
}

func closeAgentConnection(agent *agentConnection, reason string) {
	if agent == nil {
		return
	}
	agent.doneOnce.Do(func() { close(agent.done) })
	if agent.conn != nil {
		_ = agent.conn.Close(websocket.StatusPolicyViolation, reason)
	}
}

func signalAgent(agent *agentConnection) {
	if agent == nil || agent.notify == nil {
		return
	}
	select {
	case agent.notify <- struct{}{}:
	default:
	}
}
