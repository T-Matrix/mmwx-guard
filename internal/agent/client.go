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
	"io"
	"log"
	"net"
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
	"github.com/T-Matrix/mmwx-guard/internal/model"
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
	adaptive  *adaptiveController
	writeMu   sync.Mutex
	seenMu    sync.Mutex
	seen      map[string]time.Time
	resultMu  sync.Mutex
	results   map[string]cachedCommandResult
}

type cachedCommandResult struct {
	message protocol.Message
	seenAt  time.Time
}

var controlHTTPClient = &http.Client{Timeout: 30 * time.Second}

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
	return &Client{
		config: cfg, options: options, firewall: manager, collector: telemetrypkg.NewCollector(manager),
		adaptive: newAdaptiveController(manager), seen: make(map[string]time.Time), results: make(map[string]cachedCommandResult),
	}, nil
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
	resp, err := controlHTTPClient.Do(req)
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
		websocketErr := c.connect(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		log.Printf("WebSocket connection ended: %v; starting HTTPS Push/Pull fallback", websocketErr)
		fallbackCtx, stopFallback := context.WithTimeout(ctx, 10*time.Minute)
		httpsErr := c.connectHTTPS(fallbackCtx)
		stopFallback()
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if time.Since(connectedAt) >= 30*time.Second {
			backoff = time.Second
		}
		log.Printf("HTTPS fallback ended: %v; retrying WebSocket in %s", httpsErr, backoff)
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
	c.probeAndReportAddresses(ctx, conn, session)
	telemetryTicker := time.NewTicker(5 * time.Second)
	ensureTicker := time.NewTicker(30 * time.Second)
	addressTicker := time.NewTicker(30 * time.Minute)
	defer telemetryTicker.Stop()
	defer ensureTicker.Stop()
	defer addressTicker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-readErr:
			return err
		case <-telemetryTicker.C:
			t := c.collectTelemetry(ctx)
			msg, _ := protocol.NewMessage(protocol.TypeTelemetry, "", t)
			if err := c.write(ctx, conn, session, msg); err != nil {
				return err
			}
		case <-ensureTicker.C:
			ensureCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			_ = c.firewall.Ensure(ensureCtx)
			cancel()
		case <-addressTicker.C:
			c.probeAndReportAddresses(ctx, conn, session)
		}
	}
}

func (c *Client) connectHTTPS(ctx context.Context) error {
	cfg := c.currentConfig()
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
		controllerPublic, err := protocol.DecodeKey(cfg.ControllerPublicKey, ed25519.PublicKeySize)
		if err != nil {
			return errors.New("pinned controller identity key is invalid")
		}
		fingerprint = protocol.KeyFingerprint(controllerPublic)
	}
	machineID := telemetrypkg.MachineID()
	hello, _ := protocol.NewMessage(protocol.TypeHello, "", protocol.Hello{
		Name: cfg.Name, MachineID: machineID, OS: runtime.GOOS, Arch: runtime.GOARCH, Version: c.options.Version,
		Challenge: challenge, AgentEphemeralPublicKey: protocol.EncodeKey(ephemeral.PublicKey()), ControllerKeyFingerprint: fingerprint,
	})
	openResponse, err := c.openHTTPS(ctx, cfg, hello)
	if err != nil {
		return err
	}
	if openResponse.Message.Type != protocol.TypeHelloAck || protocol.ValidateFresh(openResponse.Message, time.Now(), 2*time.Minute) != nil {
		return errors.New("controller did not complete the HTTPS secure handshake")
	}
	var ack protocol.HelloAck
	if json.Unmarshal(openResponse.Message.Payload, &ack) != nil || !ack.Secure {
		return errors.New("controller HTTPS fallback does not support the required secure channel")
	}
	session, err := c.verifyControllerAndDerive(cfg, ack, ephemeral, challenge, machineID)
	if err != nil {
		return err
	}
	if err := updater.MarkAgentHealthy(c.options.StateDir, c.options.Version); err != nil {
		log.Printf("write Agent health marker: %v", err)
	}
	type outboundMessage struct {
		message   protocol.Message
		reconnect bool
	}
	verified, _ := protocol.NewMessage(protocol.TypeControllerVerified, "", protocol.ControllerVerified{Fingerprint: protocol.KeyFingerprint(mustDecodeKey(ack.ControllerPublicKey, ed25519.PublicKeySize))})
	queue := []outboundMessage{{message: verified}}
	{
		probeCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
		if report, probeErr := probePublicAddresses(probeCtx, c.currentConfig()); probeErr == nil {
			message, _ := protocol.NewMessage(protocol.TypeAddressReport, "", report)
			queue = append(queue, outboundMessage{message: message})
		} else {
			log.Printf("public address probe: %v", probeErr)
		}
		cancel()
	}
	nextTelemetry := time.Now()
	nextEnsure := time.Now().Add(30 * time.Second)
	nextAddress := time.Now().Add(30 * time.Minute)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		now := time.Now()
		if !now.Before(nextTelemetry) {
			telemetry := c.collectTelemetry(ctx)
			message, _ := protocol.NewMessage(protocol.TypeTelemetry, "", telemetry)
			queue = append(queue, outboundMessage{message: message})
			nextTelemetry = now.Add(5 * time.Second)
		}
		if !now.Before(nextEnsure) {
			ensureCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			_ = c.firewall.Ensure(ensureCtx)
			cancel()
			nextEnsure = now.Add(30 * time.Second)
		}
		if !now.Before(nextAddress) {
			probeCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
			if report, probeErr := probePublicAddresses(probeCtx, c.currentConfig()); probeErr == nil {
				message, _ := protocol.NewMessage(protocol.TypeAddressReport, "", report)
				queue = append(queue, outboundMessage{message: message})
			}
			cancel()
			nextAddress = now.Add(30 * time.Minute)
		}
		var outbound *protocol.Message
		reconnectAfterSend := false
		if len(queue) > 0 {
			outbound = &queue[0].message
			reconnectAfterSend = queue[0].reconnect
		}
		exchangeCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
		incoming, err := c.exchangeHTTPS(exchangeCtx, openResponse.SessionID, session, outbound)
		cancel()
		if err != nil {
			return err
		}
		if outbound != nil {
			queue = queue[1:]
			if reconnectAfterSend {
				return errors.New("credential rotated; renew HTTPS secure session")
			}
		}
		if incoming != nil {
			response, reconnect := c.processControllerMessage(ctx, *incoming)
			if response != nil {
				queue = append([]outboundMessage{{message: *response, reconnect: reconnect}}, queue...)
			}
		}
	}
}

func (c *Client) openHTTPS(ctx context.Context, cfg Config, hello protocol.Message) (protocol.HTTPSOpenResponse, error) {
	raw, err := json.Marshal(hello)
	if err != nil {
		return protocol.HTTPSOpenResponse{}, err
	}
	requestURL := strings.TrimRight(cfg.ControllerURL, "/") + "/api/agent/https/open?agent_id=" + url.QueryEscape(cfg.AgentID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, requestURL, bytes.NewReader(raw))
	if err != nil {
		return protocol.HTTPSOpenResponse{}, err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.Secret)
	req.Header.Set("Content-Type", "application/json")
	resp, err := controlHTTPClient.Do(req)
	if err != nil {
		return protocol.HTTPSOpenResponse{}, fmt.Errorf("open HTTPS fallback: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return protocol.HTTPSOpenResponse{}, fmt.Errorf("open HTTPS fallback: HTTP %d", resp.StatusCode)
	}
	var response protocol.HTTPSOpenResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, protocol.MaxMessageBytes)).Decode(&response); err != nil {
		return protocol.HTTPSOpenResponse{}, err
	}
	if len(response.SessionID) < 20 || len(response.SessionID) > 128 {
		return protocol.HTTPSOpenResponse{}, errors.New("controller returned an invalid HTTPS session")
	}
	return response, nil
}

func (c *Client) exchangeHTTPS(ctx context.Context, sessionID string, session *protocol.SecureSession, outbound *protocol.Message) (*protocol.Message, error) {
	exchange := protocol.HTTPSExchange{SessionID: sessionID}
	if outbound != nil {
		envelope, err := session.EncryptMessage(*outbound)
		if err != nil {
			return nil, err
		}
		exchange.Envelope = &envelope
	}
	raw, err := json.Marshal(exchange)
	if err != nil {
		return nil, err
	}
	cfg := c.currentConfig()
	requestURL := strings.TrimRight(cfg.ControllerURL, "/") + "/api/agent/https/exchange?agent_id=" + url.QueryEscape(cfg.AgentID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, requestURL, bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.Secret)
	req.Header.Set("Content-Type", "application/json")
	resp, err := controlHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("HTTPS fallback exchange: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("HTTPS fallback exchange: HTTP %d", resp.StatusCode)
	}
	var response protocol.HTTPSExchange
	if err := json.NewDecoder(io.LimitReader(resp.Body, protocol.MaxMessageBytes)).Decode(&response); err != nil {
		return nil, err
	}
	if response.SessionID != sessionID {
		return nil, errors.New("HTTPS fallback session mismatch")
	}
	if response.Envelope == nil {
		return nil, nil
	}
	message, err := session.DecryptMessage(*response.Envelope)
	if err != nil {
		return nil, err
	}
	return &message, nil
}

func (c *Client) collectTelemetry(ctx context.Context) model.Telemetry {
	telemetry := c.collector.Collect(ctx)
	if transition, err := c.adaptive.Observe(ctx, &telemetry); err != nil {
		log.Printf("adaptive protection: %v", err)
	} else if transition == "activated" {
		log.Printf("adaptive emergency protection activated: %s", telemetry.Adaptive.Reason)
	} else if transition == "recovered" {
		log.Printf("adaptive emergency protection recovered")
	}
	return telemetry
}

func (c *Client) probeAndReportAddresses(ctx context.Context, conn *websocket.Conn, session *protocol.SecureSession) {
	probeCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	report, err := probePublicAddresses(probeCtx, c.currentConfig())
	if err != nil {
		log.Printf("public address probe: %v", err)
		return
	}
	msg, err := protocol.NewMessage(protocol.TypeAddressReport, "", report)
	if err != nil {
		return
	}
	if err := c.write(ctx, conn, session, msg); err != nil {
		log.Printf("public address report: %v", err)
	}
}

func probePublicAddresses(ctx context.Context, cfg Config) (protocol.AddressReport, error) {
	type result struct {
		family  string
		address string
		err     error
	}
	results := make(chan result, 2)
	for _, family := range []string{"tcp4", "tcp6"} {
		go func() {
			address, err := probePublicAddress(ctx, cfg, family)
			results <- result{family: family, address: address, err: err}
		}()
	}
	report := protocol.AddressReport{}
	errorsByFamily := make([]string, 0, 2)
	for range 2 {
		result := <-results
		if result.err != nil {
			errorsByFamily = append(errorsByFamily, result.family+": "+result.err.Error())
			continue
		}
		if result.family == "tcp4" {
			report.IPv4 = result.address
		} else {
			report.IPv6 = result.address
		}
	}
	if report.IPv4 == "" && report.IPv6 == "" {
		return report, errors.New(strings.Join(errorsByFamily, "; "))
	}
	return report, nil
}

func probePublicAddress(ctx context.Context, cfg Config, family string) (string, error) {
	if family != "tcp4" && family != "tcp6" {
		return "", errors.New("unsupported address family")
	}
	dialer := net.Dialer{Timeout: 6 * time.Second, KeepAlive: -1}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
			return dialer.DialContext(ctx, family, address)
		},
		DisableKeepAlives: true,
	}
	defer transport.CloseIdleConnections()
	requestURL := strings.TrimRight(cfg.ControllerURL, "/") + "/api/agent/address?agent_id=" + url.QueryEscape(cfg.AgentID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, requestURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+cfg.Secret)
	resp, err := (&http.Client{Transport: transport}).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var payload struct {
		Address string `json:"address"`
	}
	decoder := json.NewDecoder(io.LimitReader(resp.Body, 4096))
	if err := decoder.Decode(&payload); err != nil {
		return "", err
	}
	address, err := netip.ParseAddr(strings.TrimSpace(payload.Address))
	if err != nil {
		return "", errors.New("controller returned an invalid address")
	}
	address = address.Unmap()
	report := protocol.AddressReport{}
	if family == "tcp4" {
		report.IPv4 = address.String()
	} else {
		report.IPv6 = address.String()
	}
	if err := protocol.ValidateAddressReport(report); err != nil {
		return "", err
	}
	return address.String(), nil
}

func (c *Client) readLoop(ctx context.Context, conn *websocket.Conn, session *protocol.SecureSession) error {
	for {
		msg, err := readControllerMessage(ctx, conn, session)
		if err != nil {
			return err
		}
		response, reconnect := c.processControllerMessage(ctx, msg)
		if response != nil {
			if err := c.write(ctx, conn, session, *response); err != nil {
				return err
			}
		}
		if reconnect {
			return errors.New("credential rotated; reconnect required")
		}
	}
}

func (c *Client) processControllerMessage(ctx context.Context, message protocol.Message) (*protocol.Message, bool) {
	if message.Type == protocol.TypePing {
		if err := protocol.ValidateFresh(message, time.Now(), 2*time.Minute); err != nil {
			return nil, false
		}
		pong, _ := protocol.NewMessage(protocol.TypePong, message.RequestID, map[string]bool{"ok": true})
		return &pong, false
	}
	if err := protocol.ValidateCommand(message, time.Now()); err != nil {
		return nil, false
	}
	if cached, ok := c.cachedResult(message.RequestID); ok {
		return &cached, false
	}
	resultType := protocol.TypeApplyResult
	if message.Type == protocol.TypeUpdateAgent {
		resultType = protocol.TypeUpdateResult
	} else if message.Type == protocol.TypeRotateCredential {
		resultType = protocol.TypeRotateResult
	}
	result := func(success bool, text string, revision int64, reconnect bool) (*protocol.Message, bool) {
		response, _ := protocol.NewMessage(resultType, message.RequestID, protocol.ApplyResult{Success: success, Message: text, Revision: revision})
		c.cacheResult(response)
		return &response, reconnect
	}
	if err := c.acceptCommand(message); err != nil {
		return result(false, err.Error(), 0, false)
	}
	switch message.Type {
	case protocol.TypeApplyPolicy:
		var payload protocol.ApplyPolicy
		if json.Unmarshal(message.Payload, &payload) != nil {
			return result(false, "invalid policy payload", 0, false)
		}
		applyCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		err := c.firewall.Apply(applyCtx, payload.Policy)
		cancel()
		if err != nil {
			return result(false, err.Error(), payload.Policy.Revision, false)
		}
		return result(true, "policy applied", payload.Policy.Revision, false)
	case protocol.TypeRollback:
		rollbackCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		err := c.firewall.Rollback(rollbackCtx)
		cancel()
		if err != nil {
			return result(false, err.Error(), 0, false)
		}
		return result(true, "policy rolled back", 0, false)
	case protocol.TypeUpdateAgent:
		var payload protocol.AgentUpdate
		if json.Unmarshal(message.Payload, &payload) != nil {
			return result(false, "invalid Agent update payload", 0, false)
		}
		err := updater.QueueAgentUpdate(filepath.Join(c.options.StateDir, "agent-update"), c.currentConfig().ControllerURL, c.options.Version, updater.AgentRequest{
			Version: payload.Version, SHA256: payload.SHA256, Size: payload.Size,
		})
		if err != nil {
			return result(false, err.Error(), 0, false)
		}
		return result(true, "Agent 更新任务已提交", 0, false)
	case protocol.TypeRotateCredential:
		var payload protocol.RotateCredential
		if json.Unmarshal(message.Payload, &payload) != nil || len(payload.Secret) < 20 || len(payload.Secret) > 128 {
			return result(false, "invalid credential rotation payload", 0, false)
		}
		updated := c.currentConfig()
		updated.Secret = payload.Secret
		if err := saveConfig(credentialOverridePath(c.options), updated); err != nil {
			return result(false, err.Error(), 0, false)
		}
		c.replaceConfig(updated)
		return result(true, "Agent credential rotated", 0, true)
	case protocol.TypeSyncBans:
		var payload protocol.SyncBans
		if json.Unmarshal(message.Payload, &payload) != nil || protocol.ValidateSyncBans(payload, time.Now()) != nil {
			return result(false, "invalid IP ban payload", 0, false)
		}
		applyCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		err := c.firewall.SyncBans(applyCtx, payload.Bans)
		cancel()
		if err != nil {
			return result(false, err.Error(), 0, false)
		}
		return result(true, "IP bans synchronized", 0, false)
	default:
		return result(false, "unsupported controller command", 0, false)
	}
}

func (c *Client) cacheResult(message protocol.Message) {
	if message.RequestID == "" {
		return
	}
	now := time.Now()
	c.resultMu.Lock()
	defer c.resultMu.Unlock()
	if c.results == nil {
		c.results = make(map[string]cachedCommandResult)
	}
	for requestID, cached := range c.results {
		if now.Sub(cached.seenAt) > 10*time.Minute {
			delete(c.results, requestID)
		}
	}
	c.results[message.RequestID] = cachedCommandResult{message: message, seenAt: now}
}

func (c *Client) cachedResult(requestID string) (protocol.Message, bool) {
	c.resultMu.Lock()
	defer c.resultMu.Unlock()
	cached, ok := c.results[requestID]
	if !ok || time.Since(cached.seenAt) > 10*time.Minute {
		delete(c.results, requestID)
		return protocol.Message{}, false
	}
	cached.message.SentAt = time.Now().UTC().Format(time.RFC3339Nano)
	c.results[requestID] = cached
	return cached.message, true
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
