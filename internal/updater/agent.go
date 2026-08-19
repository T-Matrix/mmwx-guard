package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	agentRequestFilename = "request.json"
	agentStatusFilename  = "status.json"
	agentHealthyFilename = "healthy.json"
)

type AgentRequest struct {
	Version       string `json:"version"`
	SHA256        string `json:"sha256"`
	Size          int64  `json:"size"`
	ControllerURL string `json:"controller_url"`
	RequestedAt   string `json:"requested_at"`
}

type AgentApplyOptions struct {
	UpdateDir   string
	InstallPath string
	ServiceName string
	StateDir    string
}

func QueueAgentUpdate(updateDir, controllerURL, currentVersion string, request AgentRequest) error {
	if !ValidVersion(request.Version) || !IsNewer(request.Version, currentVersion) {
		return fmt.Errorf("version %s is not newer than %s", request.Version, currentVersion)
	}
	if !sha256Pattern.MatchString(strings.ToLower(request.SHA256)) || request.Size < 1 || request.Size > maxAssetSize {
		return errors.New("invalid Agent update hash or size")
	}
	controllerURL = strings.TrimRight(controllerURL, "/")
	parsed, err := url.Parse(controllerURL)
	if err != nil || (parsed.Scheme != "https" && !(parsed.Scheme == "http" && (parsed.Hostname() == "127.0.0.1" || parsed.Hostname() == "localhost"))) || parsed.Host == "" {
		return errors.New("Agent update controller URL is invalid")
	}
	request.ControllerURL = controllerURL
	request.RequestedAt = time.Now().UTC().Format(time.RFC3339Nano)
	if err := os.MkdirAll(updateDir, 0700); err != nil {
		return err
	}
	for _, name := range []string{agentRequestFilename, "processing.json"} {
		if _, err := os.Stat(filepath.Join(updateDir, name)); err == nil {
			return errors.New("an Agent update is already in progress")
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return writeJSONAtomic(filepath.Join(updateDir, agentRequestFilename), request, 0600)
}

func MarkAgentHealthy(stateDir, version string) error {
	updateDir := filepath.Join(stateDir, "agent-update")
	if err := os.MkdirAll(updateDir, 0700); err != nil {
		return err
	}
	return writeJSONAtomic(filepath.Join(updateDir, agentHealthyFilename), map[string]string{
		"version": version, "connected_at": time.Now().UTC().Format(time.RFC3339Nano),
	}, 0600)
}

func ApplyAgentUpdate(ctx context.Context, options AgentApplyOptions) (returnErr error) {
	if options.UpdateDir == "" || options.InstallPath == "" || options.StateDir == "" {
		return errors.New("Agent update paths are required")
	}
	requestPath := filepath.Join(options.UpdateDir, agentRequestFilename)
	processingPath := filepath.Join(options.UpdateDir, "processing.json")
	if err := os.Rename(requestPath, processingPath); err != nil {
		return fmt.Errorf("claim Agent update request: %w", err)
	}
	defer os.Remove(processingPath)
	raw, err := os.ReadFile(processingPath)
	if err != nil {
		return err
	}
	var request AgentRequest
	if err := json.Unmarshal(raw, &request); err != nil {
		return err
	}
	if !ValidVersion(request.Version) || !sha256Pattern.MatchString(strings.ToLower(request.SHA256)) || request.Size < 1 || request.Size > maxAssetSize {
		return errors.New("Agent update request is invalid")
	}
	statusPath := filepath.Join(options.UpdateDir, agentStatusFilename)
	setStatus := func(state, message string) {
		_ = writeJSONAtomic(statusPath, Status{State: state, Version: request.Version, Message: message, UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano)}, 0600)
	}
	defer func() {
		if returnErr != nil {
			setStatus("failed", returnErr.Error())
		}
	}()

	setStatus("downloading", "正在下载并校验新版 Agent")
	assetName := "mmwx-guard-agent-linux-" + runtime.GOARCH
	temporary, err := os.CreateTemp(filepath.Dir(options.InstallPath), ".agent-update-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := downloadAgentAsset(ctx, request.ControllerURL+"/downloads/"+assetName, request, temporary); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Chmod(0755); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := verifyBinaryVersion(ctx, temporaryPath, request.Version); err != nil {
		return err
	}

	setStatus("installing", "正在停止服务并原子替换 Agent")
	if err := controlService(ctx, "stop", options.ServiceName); err != nil {
		return err
	}
	backupPath := options.InstallPath + ".previous"
	if err := copyFile(options.InstallPath, backupPath, 0755); err != nil {
		_ = controlService(context.Background(), "start", options.ServiceName)
		return fmt.Errorf("backup Agent: %w", err)
	}
	if err := installFileAtomic(temporaryPath, options.InstallPath, 0755); err != nil {
		_ = controlService(context.Background(), "start", options.ServiceName)
		return fmt.Errorf("install Agent: %w", err)
	}
	healthyPath := filepath.Join(options.StateDir, "agent-update", agentHealthyFilename)
	_ = os.Remove(healthyPath)
	if err := controlService(ctx, "start", options.ServiceName); err != nil {
		_ = installFileAtomic(backupPath, options.InstallPath, 0755)
		_ = controlService(context.Background(), "start", options.ServiceName)
		return fmt.Errorf("start updated Agent: %w", err)
	}
	if err := waitForAgentHealthy(ctx, healthyPath, request.Version, 45*time.Second); err != nil {
		_ = controlService(context.Background(), "stop", options.ServiceName)
		_ = installFileAtomic(backupPath, options.InstallPath, 0755)
		_ = controlService(context.Background(), "start", options.ServiceName)
		return fmt.Errorf("updated Agent did not reconnect and was rolled back: %w", err)
	}
	setStatus("completed", "Agent 已更新到 "+request.Version)
	return nil
}

func downloadAgentAsset(ctx context.Context, assetURL string, request AgentRequest, dst io.Writer) error {
	parsed, err := url.Parse(assetURL)
	if err != nil || (parsed.Scheme != "https" && !(parsed.Scheme == "http" && (parsed.Hostname() == "127.0.0.1" || parsed.Hostname() == "localhost"))) {
		return errors.New("invalid Agent asset URL")
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodGet, assetURL, nil)
	if err != nil {
		return err
	}
	response, err := (&http.Client{Timeout: 2 * time.Minute}).Do(httpRequest)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("download Agent: HTTP %d", response.StatusCode)
	}
	hash := sha256.New()
	written, err := io.Copy(io.MultiWriter(dst, hash), io.LimitReader(response.Body, maxAssetSize+1))
	if err != nil {
		return err
	}
	if written != request.Size {
		return fmt.Errorf("Agent size mismatch: got %d, want %d", written, request.Size)
	}
	if hex.EncodeToString(hash.Sum(nil)) != strings.ToLower(request.SHA256) {
		return errors.New("Agent SHA-256 mismatch")
	}
	return nil
}

func controlService(ctx context.Context, action, service string) error {
	if service == "" || strings.ContainsAny(service, `/\\`) || (action != "start" && action != "stop") {
		return errors.New("invalid Agent service operation")
	}
	commandCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	output, err := exec.CommandContext(commandCtx, "systemctl", action, service).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %s: %w: %s", action, err, strings.TrimSpace(string(output)))
	}
	return nil
}

func waitForAgentHealthy(ctx context.Context, path, version string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		raw, err := os.ReadFile(path)
		if err == nil {
			var marker map[string]string
			if json.Unmarshal(raw, &marker) == nil && marker["version"] == version {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
	return errors.New("timed out waiting for Agent health marker")
}
