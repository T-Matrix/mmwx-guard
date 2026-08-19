package agent

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"

	"github.com/T-Matrix/mmwx-guard/internal/firewall"
	"github.com/T-Matrix/mmwx-guard/internal/protocol"
	telemetrypkg "github.com/T-Matrix/mmwx-guard/internal/telemetry"
	"github.com/T-Matrix/mmwx-guard/internal/updater"
)

type Config struct {
	ControllerURL       string `json:"controller_url"`
	ControllerPublicKey string `json:"controller_public_key,omitempty"`
	AgentID             string `json:"agent_id"`
	Secret              string `json:"secret"`
	Name                string `json:"name"`
}

type Options struct {
	ConfigPath string
	StateDir   string
	Version    string
	DryRun     bool
}

type Client struct {
	config    Config
	configMu  sync.RWMutex
	options   Options
	firewall  *firewall.Manager
	collector *telemetrypkg.Collector
	writeMu   sync.Mutex
	seenMu    sync.Mutex
	seen      map[string]time.Time
}

func LoadOrEnroll(ctx context.Context, options Options, controllerURL, token, name string) (*Client, error) {
	var cfg Config
	raw, err := os.ReadFile(options.ConfigPath)
	if err == nil {
		if err := json.Unmarshal(raw, &cfg); err != nil {
			return nil, fmt.Errorf("decode agent config: %w", err)
		}
		if override, overrideErr := loadCredentialOverride(options, cfg); overrideErr != nil {
			return nil, overrideErr
		} else if override != nil {
			cfg.Secret = override.Secret
			cfg.ControllerPublicKey = override.ControllerPublicKey
		}
	} else {
		if token == "" || controllerURL == "" {
			return nil, errors.New("agent is not enrolled; --controller and --token are required")
		}
		if name == "" {
			name, _ = os.Hostname()
		}
		cfg, err = enroll(ctx, controllerURL, token, name, options.Version)
		if err != nil {
			return nil, err
		}
		if err := saveConfig(options.ConfigPath, cfg); err != nil {
			return nil, err
		}
	}
	if err := validateControllerURL(cfg.ControllerURL); err != nil {
		return nil, err
	}
	if cfg.AgentID == "" || cfg.Secret == "" {
		return nil, errors.New("agent credentials are incomplete")
	}
	manager := firewall.NewManager(options.StateDir, options.DryRun)
	return &Client{config: cfg, options: options, firewall: manager, collector: telemetrypkg.NewCollector(manager), seen: make(map[string]time.Time)}, nil
}

func EnrollOnly(ctx context.Context, options Options, controllerURL, token, name string, replace bool) error {
	if token == "" || controllerURL == "" {
		return errors.New("--controller and --token are required for enrollment")
	}
	if _, err := os.Stat(options.ConfigPath); err == nil {
		if !replace {
			return errors.New("agent is already enrolled; remove its config before enrolling again")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("check agent config: %w", err)
	}
	if name == "" {
		name, _ = os.Hostname()
	}
	cfg, err := enroll(ctx, controllerURL, token, name, options.Version)
	if err != nil {
		return err
	}
	if err := saveConfig(options.ConfigPath, cfg); err != nil {
		return err
	}
	return saveConfig(credentialOverridePath(options), cfg)
}

func enroll(ctx context.Context, controllerURL, token, name, version string) (Config, error) {
	if err := validateControllerURL(controllerURL); err != nil {
		return Config{}, err
	}
	body := map[string]string{
		"token": token, "name": name, "machine_id": telemetrypkg.MachineID(),
		"os": runtime.GOOS, "arch": runtime.GOARCH, "version": version,
	}
	raw, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(controllerURL, "/")+"/api/agent/enroll", bytes.NewReader(raw))
	if err != nil {
		return Config{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return Config{}, fmt.Errorf("enroll agent: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		var apiErr struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&apiErr)
		return Config{}, fmt.Errorf("enroll agent: HTTP %d: %s", resp.StatusCode, apiErr.Error)
	}
	var result struct {
		AgentID             string `json:"agent_id"`
		Secret              string `json:"secret"`
		ControllerPublicKey string `json:"controller_public_key"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return Config{}, err
	}
	if _, err := protocol.DecodeKey(result.ControllerPublicKey, ed25519.PublicKeySize); err != nil {
		return Config{}, errors.New("enroll agent: controller identity key is invalid")
	}
	return Config{ControllerURL: strings.TrimRight(controllerURL, "/"), ControllerPublicKey: result.ControllerPublicKey, AgentID: result.AgentID, Secret: result.Secret, Name: name}, nil
}

func validateControllerURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return errors.New("controller URL must be an HTTPS origin without a path, query, or credentials")
	}
	if u.Scheme == "https" {
		return nil
	}
	if u.Scheme == "http" {
		host := strings.ToLower(u.Hostname())
		if host == "localhost" {
			return nil
		}
		if address, parseErr := netip.ParseAddr(host); parseErr == nil && address.IsLoopback() {
			return nil
		}
	}
	return errors.New("controller URL must use HTTPS; HTTP is allowed only for localhost")
}

func saveConfig(path string, cfg Config) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	raw, _ := json.MarshalIndent(cfg, "", "  ")
	temporary, err := os.CreateTemp(filepath.Dir(path), ".agent-config-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(raw); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}

func credentialOverridePath(options Options) string {
	return filepath.Join(options.StateDir, "agent-credentials.json")
}

func loadCredentialOverride(options Options, base Config) (*Config, error) {
	raw, err := os.ReadFile(credentialOverridePath(options))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read Agent credential override: %w", err)
	}
	var override Config
	if err := json.Unmarshal(raw, &override); err != nil {
		return nil, fmt.Errorf("decode Agent credential override: %w", err)
	}
	if override.AgentID != base.AgentID || override.ControllerURL != base.ControllerURL || override.Secret == "" {
		return nil, errors.New("Agent credential override does not match the enrolled Agent")
	}
	return &override, nil
}

func (c *Client) Run(ctx context.Context) error {
	backoff := time.Second
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		connectedAt := time.Now()
		err := c.connect(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if time.Since(connectedAt) >= 30*time.Second {
			backoff = time.Second
		}
		log.Printf("controller connection ended: %v; reconnecting in %s", err, backoff)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

func (c *Client) connect(ctx context.Context) error {
	cfg := c.currentConfig()
	u, err := url.Parse(cfg.ControllerURL)
	if err != nil {
		return err
	}
	switch u.Scheme {
	case "http":
		u.Scheme = "ws"
	case "https":
		u.Scheme = "wss"
	default:
		return errors.New("controller URL must use http or https")
	}
	u.Path = "/api/agent/ws"
	q := u.Query()
	q.Set("agent_id", cfg.AgentID)
	u.RawQuery = q.Encode()
	header := http.Header{}
	header.Set("Authorization", "Bearer "+cfg.Secret)
	conn, _, err := websocket.Dial(ctx, u.String(), &websocket.DialOptions{HTTPHeader: header})
	if err != nil {
		return err
	}
	defer conn.Close(websocket.StatusNormalClosure, "agent reconnect")
	conn.SetReadLimit(protocol.MaxMessageBytes)
	ephemeral, err := protocol.GenerateEphemeralKey()
	if err != nil {
		return err
	}
	challengeBytes := make([]byte, 32)
	if _, err := rand.Read(challengeBytes); err != nil {
		return err
	}
	challenge := protocol.EncodeKey(challengeBytes)
	fingerprint := ""
	if cfg.ControllerPublicKey != "" {
		controllerPublic, decodeErr := protocol.DecodeKey(cfg.ControllerPublicKey, ed25519.PublicKeySize)
		if decodeErr != nil {
			return errors.New("pinned controller identity key is invalid")
		}
		fingerprint = protocol.KeyFingerprint(controllerPublic)
	}
	machineID := telemetrypkg.MachineID()
	hello, _ := protocol.NewMessage(protocol.TypeHello, "", protocol.Hello{
		Name: cfg.Name, MachineID: machineID, OS: runtime.GOOS, Arch: runtime.GOARCH, Version: c.options.Version,
		Challenge: challenge, AgentEphemeralPublicKey: protocol.EncodeKey(ephemeral.PublicKey()), ControllerKeyFingerprint: fingerprint,
	})
	if err := c.write(ctx, conn, nil, hello); err != nil {
		return err
	}
	readCtx, stopRead := context.WithTimeout(ctx, 15*time.Second)
	var ackMessage protocol.Message
	err = wsjson.Read(readCtx, conn, &ackMessage)
	stopRead()
	if err != nil || ackMessage.Type != protocol.TypeHelloAck || protocol.ValidateFresh(ackMessage, time.Now(), 2*time.Minute) != nil {
		return errors.New("controller did not complete the secure handshake")
	}
	var ack protocol.HelloAck
	if json.Unmarshal(ackMessage.Payload, &ack) != nil || !ack.Secure {
		return errors.New("controller does not support the required secure channel")
	}
	session, err := c.verifyControllerAndDerive(cfg, ack, ephemeral, challenge, machineID)
	if err != nil {
		return err
	}
	verified, _ := protocol.NewMessage(protocol.TypeControllerVerified, "", protocol.ControllerVerified{Fingerprint: protocol.KeyFingerprint(mustDecodeKey(ack.ControllerPublicKey, ed25519.PublicKeySize))})
	if err := c.write(ctx, conn, session, verified); err != nil {
		return err
	}
	if err := updater.MarkAgentHealthy(c.options.StateDir, c.options.Version); err != nil {
		log.Printf("write Agent health marker: %v", err)
	}
	readErr := make(chan error, 1)
	go func() { readErr <- c.readLoop(ctx, conn, session) }()
	telemetryTicker := time.NewTicker(5 * time.Second)
	ensureTicker := time.NewTicker(30 * time.Second)
	defer telemetryTicker.Stop()
	defer ensureTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-readErr:
			return err
		case <-telemetryTicker.C:
			t := c.collector.Collect(ctx)
			msg, _ := protocol.NewMessage(protocol.TypeTelemetry, "", t)
			if err := c.write(ctx, conn, session, msg); err != nil {
				return err
			}
		case <-ensureTicker.C:
			ensureCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			_ = c.firewall.Ensure(ensureCtx)
			cancel()
		}
	}
}

func (c *Client) readLoop(ctx context.Context, conn *websocket.Conn, session *protocol.SecureSession) error {
	for {
		msg, err := readControllerMessage(ctx, conn, session)
		if err != nil {
			return err
		}
		switch msg.Type {
		case protocol.TypeApplyPolicy:
			if err := c.acceptCommand(msg); err != nil {
				c.sendResult(ctx, conn, session, protocol.TypeApplyResult, msg.RequestID, false, err.Error(), 0)
				continue
			}
			var payload protocol.ApplyPolicy
			if err := json.Unmarshal(msg.Payload, &payload); err != nil {
				c.sendResult(ctx, conn, session, protocol.TypeApplyResult, msg.RequestID, false, "invalid policy payload", 0)
				continue
			}
			applyCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			err := c.firewall.Apply(applyCtx, payload.Policy)
			cancel()
			if err != nil {
				c.sendResult(ctx, conn, session, protocol.TypeApplyResult, msg.RequestID, false, err.Error(), payload.Policy.Revision)
			} else {
				c.sendResult(ctx, conn, session, protocol.TypeApplyResult, msg.RequestID, true, "policy applied", payload.Policy.Revision)
			}
		case protocol.TypeRollback:
			if err := c.acceptCommand(msg); err != nil {
				c.sendResult(ctx, conn, session, protocol.TypeApplyResult, msg.RequestID, false, err.Error(), 0)
				continue
			}
			rollbackCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			err := c.firewall.Rollback(rollbackCtx)
			cancel()
			if err != nil {
				c.sendResult(ctx, conn, session, protocol.TypeApplyResult, msg.RequestID, false, err.Error(), 0)
			} else {
				c.sendResult(ctx, conn, session, protocol.TypeApplyResult, msg.RequestID, true, "policy rolled back", 0)
			}
		case protocol.TypeUpdateAgent:
			if err := c.acceptCommand(msg); err != nil {
				c.sendResult(ctx, conn, session, protocol.TypeUpdateResult, msg.RequestID, false, err.Error(), 0)
				continue
			}
			var payload protocol.AgentUpdate
			if err := json.Unmarshal(msg.Payload, &payload); err != nil {
				c.sendResult(ctx, conn, session, protocol.TypeUpdateResult, msg.RequestID, false, "invalid Agent update payload", 0)
				continue
			}
			err := updater.QueueAgentUpdate(filepath.Join(c.options.StateDir, "agent-update"), c.currentConfig().ControllerURL, c.options.Version, updater.AgentRequest{
				Version: payload.Version, SHA256: payload.SHA256, Size: payload.Size,
			})
			if err != nil {
				c.sendResult(ctx, conn, session, protocol.TypeUpdateResult, msg.RequestID, false, err.Error(), 0)
			} else {
				c.sendResult(ctx, conn, session, protocol.TypeUpdateResult, msg.RequestID, true, "Agent 更新任务已提交", 0)
			}
		case protocol.TypeRotateCredential:
			if err := c.acceptCommand(msg); err != nil {
				c.sendResult(ctx, conn, session, protocol.TypeRotateResult, msg.RequestID, false, err.Error(), 0)
				continue
			}
			var payload protocol.RotateCredential
			if json.Unmarshal(msg.Payload, &payload) != nil || len(payload.Secret) < 20 || len(payload.Secret) > 128 {
				c.sendResult(ctx, conn, session, protocol.TypeRotateResult, msg.RequestID, false, "invalid credential rotation payload", 0)
				continue
			}
			updated := c.currentConfig()
			updated.Secret = payload.Secret
			if err := saveConfig(credentialOverridePath(c.options), updated); err != nil {
				c.sendResult(ctx, conn, session, protocol.TypeRotateResult, msg.RequestID, false, err.Error(), 0)
				continue
			}
			c.replaceConfig(updated)
			c.sendResult(ctx, conn, session, protocol.TypeRotateResult, msg.RequestID, true, "Agent credential rotated", 0)
			return errors.New("credential rotated; reconnect required")
		case protocol.TypePing:
			pong, _ := protocol.NewMessage(protocol.TypePong, msg.RequestID, map[string]bool{"ok": true})
			_ = c.write(ctx, conn, session, pong)
		}
	}
}

func (c *Client) acceptCommand(message protocol.Message) error {
	now := time.Now()
	if err := protocol.ValidateCommand(message, now); err != nil {
		return err
	}
	c.seenMu.Lock()
	defer c.seenMu.Unlock()
	for requestID, seenAt := range c.seen {
		if now.Sub(seenAt) > 5*time.Minute {
			delete(c.seen, requestID)
		}
	}
	if _, exists := c.seen[message.RequestID]; exists {
		return errors.New("duplicate control request rejected")
	}
	c.seen[message.RequestID] = now
	return nil
}

func (c *Client) sendResult(ctx context.Context, conn *websocket.Conn, session *protocol.SecureSession, resultType, requestID string, success bool, message string, revision int64) {
	msg, _ := protocol.NewMessage(resultType, requestID, protocol.ApplyResult{Success: success, Message: message, Revision: revision})
	_ = c.write(ctx, conn, session, msg)
}

func (c *Client) write(ctx context.Context, conn *websocket.Conn, session *protocol.SecureSession, msg protocol.Message) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	writeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if session == nil {
		return wsjson.Write(writeCtx, conn, msg)
	}
	envelope, err := session.EncryptMessage(msg)
	if err != nil {
		return err
	}
	return wsjson.Write(writeCtx, conn, envelope)
}

func (c *Client) verifyControllerAndDerive(cfg Config, ack protocol.HelloAck, ephemeral *protocol.EphemeralKey, challenge, machineID string) (*protocol.SecureSession, error) {
	controllerIdentity, err := protocol.DecodeKey(ack.ControllerPublicKey, ed25519.PublicKeySize)
	if err != nil {
		return nil, errors.New("controller identity key is invalid")
	}
	if cfg.ControllerPublicKey != "" {
		pinned, decodeErr := protocol.DecodeKey(cfg.ControllerPublicKey, ed25519.PublicKeySize)
		if decodeErr != nil || subtle.ConstantTimeCompare(pinned, controllerIdentity) != 1 {
			return nil, errors.New("controller identity changed; connection rejected")
		}
	}
	controllerEphemeral, err := protocol.DecodeKey(ack.ControllerEphemeralPublicKey, 32)
	if err != nil {
		return nil, errors.New("controller ephemeral key is invalid")
	}
	signature, err := protocol.DecodeKey(ack.Signature, ed25519.SignatureSize)
	if err != nil {
		return nil, errors.New("controller handshake signature is invalid")
	}
	transcript := protocol.HandshakeTranscript(cfg.AgentID, machineID, challenge, ephemeral.PublicKey(), controllerEphemeral)
	if !ed25519.Verify(ed25519.PublicKey(controllerIdentity), transcript, signature) {
		return nil, errors.New("controller handshake signature verification failed")
	}
	if cfg.ControllerPublicKey == "" {
		cfg.ControllerPublicKey = ack.ControllerPublicKey
		if err := saveConfig(credentialOverridePath(c.options), cfg); err != nil {
			return nil, fmt.Errorf("pin controller identity: %w", err)
		}
		c.replaceConfig(cfg)
	}
	return protocol.DeriveSecureSession(ephemeral, controllerEphemeral, false)
}

func readControllerMessage(ctx context.Context, conn *websocket.Conn, session *protocol.SecureSession) (protocol.Message, error) {
	var envelope protocol.SecureEnvelope
	if err := wsjson.Read(ctx, conn, &envelope); err != nil {
		return protocol.Message{}, err
	}
	return session.DecryptMessage(envelope)
}

func (c *Client) currentConfig() Config {
	c.configMu.RLock()
	defer c.configMu.RUnlock()
	return c.config
}

func (c *Client) replaceConfig(config Config) {
	c.configMu.Lock()
	c.config = config
	c.configMu.Unlock()
}

func mustDecodeKey(value string, size int) []byte {
	decoded, _ := protocol.DecodeKey(value, size)
	return decoded
}
