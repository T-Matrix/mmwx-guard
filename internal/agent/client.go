package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
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
	ControllerURL string `json:"controller_url"`
	AgentID       string `json:"agent_id"`
	Secret        string `json:"secret"`
	Name          string `json:"name"`
}

type Options struct {
	ConfigPath string
	StateDir   string
	Version    string
	DryRun     bool
}

type Client struct {
	config    Config
	options   Options
	firewall  *firewall.Manager
	collector *telemetrypkg.Collector
	writeMu   sync.Mutex
}

func LoadOrEnroll(ctx context.Context, options Options, controllerURL, token, name string) (*Client, error) {
	var cfg Config
	raw, err := os.ReadFile(options.ConfigPath)
	if err == nil {
		if err := json.Unmarshal(raw, &cfg); err != nil {
			return nil, fmt.Errorf("decode agent config: %w", err)
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
	manager := firewall.NewManager(options.StateDir, options.DryRun)
	return &Client{config: cfg, options: options, firewall: manager, collector: telemetrypkg.NewCollector(manager)}, nil
}

func EnrollOnly(ctx context.Context, options Options, controllerURL, token, name string) error {
	if token == "" || controllerURL == "" {
		return errors.New("--controller and --token are required for enrollment")
	}
	if _, err := os.Stat(options.ConfigPath); err == nil {
		return errors.New("agent is already enrolled; remove its config before enrolling again")
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
	return saveConfig(options.ConfigPath, cfg)
}

func enroll(ctx context.Context, controllerURL, token, name, version string) (Config, error) {
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
		AgentID string `json:"agent_id"`
		Secret  string `json:"secret"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return Config{}, err
	}
	return Config{ControllerURL: strings.TrimRight(controllerURL, "/"), AgentID: result.AgentID, Secret: result.Secret, Name: name}, nil
}

func saveConfig(path string, cfg Config) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	raw, _ := json.MarshalIndent(cfg, "", "  ")
	return os.WriteFile(path, raw, 0600)
}

func (c *Client) Run(ctx context.Context) error {
	backoff := time.Second
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := c.connect(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
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
	u, err := url.Parse(c.config.ControllerURL)
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
	q.Set("agent_id", c.config.AgentID)
	u.RawQuery = q.Encode()
	header := http.Header{}
	header.Set("Authorization", "Bearer "+c.config.Secret)
	conn, _, err := websocket.Dial(ctx, u.String(), &websocket.DialOptions{HTTPHeader: header})
	if err != nil {
		return err
	}
	defer conn.Close(websocket.StatusNormalClosure, "agent reconnect")
	conn.SetReadLimit(2 << 20)
	hello, _ := protocol.NewMessage(protocol.TypeHello, "", protocol.Hello{
		Name: c.config.Name, MachineID: telemetrypkg.MachineID(), OS: runtime.GOOS, Arch: runtime.GOARCH, Version: c.options.Version,
	})
	if err := c.write(ctx, conn, hello); err != nil {
		return err
	}
	readErr := make(chan error, 1)
	go func() { readErr <- c.readLoop(ctx, conn) }()
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
			if err := c.write(ctx, conn, msg); err != nil {
				return err
			}
		case <-ensureTicker.C:
			ensureCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			_ = c.firewall.Ensure(ensureCtx)
			cancel()
		}
	}
}

func (c *Client) readLoop(ctx context.Context, conn *websocket.Conn) error {
	for {
		var msg protocol.Message
		if err := wsjson.Read(ctx, conn, &msg); err != nil {
			return err
		}
		switch msg.Type {
		case protocol.TypeHelloAck:
			if err := updater.MarkAgentHealthy(c.options.StateDir, c.options.Version); err != nil {
				log.Printf("write Agent health marker: %v", err)
			}
		case protocol.TypeApplyPolicy:
			var payload protocol.ApplyPolicy
			if err := json.Unmarshal(msg.Payload, &payload); err != nil {
				c.sendResult(ctx, conn, protocol.TypeApplyResult, msg.RequestID, false, "invalid policy payload", 0)
				continue
			}
			applyCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			err := c.firewall.Apply(applyCtx, payload.Policy)
			cancel()
			if err != nil {
				c.sendResult(ctx, conn, protocol.TypeApplyResult, msg.RequestID, false, err.Error(), payload.Policy.Revision)
			} else {
				c.sendResult(ctx, conn, protocol.TypeApplyResult, msg.RequestID, true, "policy applied", payload.Policy.Revision)
			}
		case protocol.TypeRollback:
			rollbackCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			err := c.firewall.Rollback(rollbackCtx)
			cancel()
			if err != nil {
				c.sendResult(ctx, conn, protocol.TypeApplyResult, msg.RequestID, false, err.Error(), 0)
			} else {
				c.sendResult(ctx, conn, protocol.TypeApplyResult, msg.RequestID, true, "policy rolled back", 0)
			}
		case protocol.TypeUpdateAgent:
			var payload protocol.AgentUpdate
			if err := json.Unmarshal(msg.Payload, &payload); err != nil {
				c.sendResult(ctx, conn, protocol.TypeUpdateResult, msg.RequestID, false, "invalid Agent update payload", 0)
				continue
			}
			err := updater.QueueAgentUpdate(filepath.Join(c.options.StateDir, "agent-update"), c.config.ControllerURL, c.options.Version, updater.AgentRequest{
				Version: payload.Version, SHA256: payload.SHA256, Size: payload.Size,
			})
			if err != nil {
				c.sendResult(ctx, conn, protocol.TypeUpdateResult, msg.RequestID, false, err.Error(), 0)
			} else {
				c.sendResult(ctx, conn, protocol.TypeUpdateResult, msg.RequestID, true, "Agent 更新任务已提交", 0)
			}
		case protocol.TypePing:
			pong, _ := protocol.NewMessage(protocol.TypePong, msg.RequestID, map[string]bool{"ok": true})
			_ = c.write(ctx, conn, pong)
		}
	}
}

func (c *Client) sendResult(ctx context.Context, conn *websocket.Conn, resultType, requestID string, success bool, message string, revision int64) {
	msg, _ := protocol.NewMessage(resultType, requestID, protocol.ApplyResult{Success: success, Message: message, Revision: revision})
	_ = c.write(ctx, conn, msg)
}

func (c *Client) write(ctx context.Context, conn *websocket.Conn, msg protocol.Message) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	writeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return wsjson.Write(writeCtx, conn, msg)
}
