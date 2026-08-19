package updater

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type ApplyOptions struct {
	Repository  string
	UpdateDir   string
	InstallPath string
	AgentDir    string
	ServiceName string
	HealthURL   string
}

func ApplyControllerUpdate(ctx context.Context, options ApplyOptions) (returnErr error) {
	if !ValidRepository(options.Repository) {
		return fmt.Errorf("invalid release repository %q", options.Repository)
	}
	requestPath := filepath.Join(options.UpdateDir, requestFilename)
	processingPath := filepath.Join(options.UpdateDir, "processing.json")
	if err := os.Rename(requestPath, processingPath); err != nil {
		return fmt.Errorf("claim update request: %w", err)
	}
	defer os.Remove(processingPath)
	requestRaw, err := os.ReadFile(processingPath)
	if err != nil {
		return fmt.Errorf("read update request: %w", err)
	}
	var request Request
	if err := json.Unmarshal(requestRaw, &request); err != nil {
		return fmt.Errorf("decode update request: %w", err)
	}
	if request.Repository != options.Repository || !ValidVersion(request.Version) {
		return errors.New("update request repository or version is invalid")
	}
	statusPath := filepath.Join(options.UpdateDir, statusFilename)
	setStatus := func(state, message string) {
		_ = writeJSONAtomic(statusPath, Status{
			State: state, Version: request.Version, Message: message,
			UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano),
		}, 0600)
	}
	defer func() {
		if returnErr != nil {
			setStatus("failed", returnErr.Error())
		}
	}()

	setStatus("downloading", "正在下载并校验更新文件")
	client := ReleaseClient{Repository: options.Repository}
	manifest, err := client.Version(ctx, request.Version)
	if err != nil {
		return err
	}
	if manifest.Version != request.Version {
		return errors.New("release manifest version mismatch")
	}

	assetNames := []string{
		"mmwx-guard-linux-" + runtime.GOARCH,
		"mmwx-guard-agent-linux-amd64",
		"mmwx-guard-agent-linux-arm64",
	}
	stagingDir, err := os.MkdirTemp(options.UpdateDir, ".staging-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stagingDir)
	for _, name := range assetNames {
		asset, ok := manifest.Assets[name]
		if !ok {
			return fmt.Errorf("release is missing %s", name)
		}
		path := filepath.Join(stagingDir, name)
		file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0755)
		if err != nil {
			return err
		}
		downloadErr := client.Download(ctx, manifest.Version, name, asset, file)
		closeErr := file.Close()
		if downloadErr != nil {
			return downloadErr
		}
		if closeErr != nil {
			return closeErr
		}
		if isNativeAsset(name, runtime.GOARCH) {
			if err := verifyBinaryVersion(ctx, path, manifest.Version); err != nil {
				return fmt.Errorf("validate %s: %w", name, err)
			}
		}
	}

	setStatus("installing", "校验通过，正在安装并保留回滚副本")
	backupDir := filepath.Join(options.UpdateDir, "backups", strings.TrimPrefix(request.CurrentBuild, "v")+"-to-"+strings.TrimPrefix(request.Version, "v"))
	if err := os.RemoveAll(backupDir); err != nil {
		return err
	}
	if err := os.MkdirAll(backupDir, 0700); err != nil {
		return err
	}
	targets := []struct{ source, target, backup string }{
		{filepath.Join(stagingDir, assetNames[0]), options.InstallPath, filepath.Join(backupDir, "mmwx-guard")},
		{filepath.Join(stagingDir, assetNames[1]), filepath.Join(options.AgentDir, assetNames[1]), filepath.Join(backupDir, assetNames[1])},
		{filepath.Join(stagingDir, assetNames[2]), filepath.Join(options.AgentDir, assetNames[2]), filepath.Join(backupDir, assetNames[2])},
	}
	installed := make([]struct{ target, backup string }, 0, len(targets))
	for _, target := range targets {
		if err := copyFile(target.target, target.backup, 0755); err != nil {
			return fmt.Errorf("backup %s: %w", target.target, err)
		}
		if err := installFileAtomic(target.source, target.target, 0755); err != nil {
			rollbackFiles(installed)
			return fmt.Errorf("install %s: %w", target.target, err)
		}
		installed = append(installed, struct{ target, backup string }{target.target, target.backup})
	}

	setStatus("restarting", "文件安装完成，正在重启主控")
	if err := restartService(ctx, options.ServiceName); err != nil {
		rollbackFiles(installed)
		_ = restartService(context.Background(), options.ServiceName)
		return fmt.Errorf("restart controller: %w", err)
	}
	if err := waitForHealth(ctx, options.HealthURL, manifest.Version, 40*time.Second); err != nil {
		rollbackFiles(installed)
		_ = restartService(context.Background(), options.ServiceName)
		return fmt.Errorf("updated controller failed health check and was rolled back: %w", err)
	}
	setStatus("completed", "主控与内置 Agent 已更新到 "+manifest.Version)
	return nil
}

func isNativeAsset(name, arch string) bool {
	return strings.HasSuffix(name, "-"+arch)
}

func verifyBinaryVersion(ctx context.Context, path, expected string) error {
	commandCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	output, err := exec.CommandContext(commandCtx, path, "--version").CombinedOutput()
	if err != nil {
		return fmt.Errorf("execute --version: %w: %s", err, strings.TrimSpace(string(output)))
	}
	if strings.TrimSpace(string(output)) != expected {
		return fmt.Errorf("version mismatch: got %q, want %q", strings.TrimSpace(string(output)), expected)
	}
	return nil
}

func installFileAtomic(source, target string, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(target), ".install-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	sourceFile, err := os.Open(source)
	if err != nil {
		temporary.Close()
		return err
	}
	_, copyErr := io.Copy(temporary, sourceFile)
	closeSourceErr := sourceFile.Close()
	if copyErr != nil {
		temporary.Close()
		return copyErr
	}
	if closeSourceErr != nil {
		temporary.Close()
		return closeSourceErr
	}
	if err := temporary.Chmod(mode); err != nil {
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
	return os.Rename(temporaryPath, target)
}

func copyFile(source, target string, mode os.FileMode) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
		return err
	}
	output, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err := io.Copy(output, input); err != nil {
		output.Close()
		return err
	}
	if err := output.Sync(); err != nil {
		output.Close()
		return err
	}
	return output.Close()
}

func rollbackFiles(installed []struct{ target, backup string }) {
	for index := len(installed) - 1; index >= 0; index-- {
		_ = installFileAtomic(installed[index].backup, installed[index].target, 0755)
	}
}

func restartService(ctx context.Context, service string) error {
	if service == "" || strings.ContainsAny(service, `/\\`) {
		return errors.New("invalid systemd service name")
	}
	commandCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	output, err := exec.CommandContext(commandCtx, "systemctl", "restart", service).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl restart: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func waitForHealth(ctx context.Context, url, expectedVersion string, timeout time.Duration) error {
	if url == "" {
		return errors.New("health URL is required")
	}
	deadline := time.Now().Add(timeout)
	client := &http.Client{Timeout: 3 * time.Second}
	var lastErr error
	for time.Now().Before(deadline) {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err == nil {
			response, requestErr := client.Do(request)
			if requestErr == nil {
				var result struct {
					OK      bool   `json:"ok"`
					Version string `json:"version"`
				}
				decodeErr := json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&result)
				response.Body.Close()
				if response.StatusCode == http.StatusOK && decodeErr == nil && result.OK && result.Version == expectedVersion {
					return nil
				}
				lastErr = fmt.Errorf("unexpected health response: HTTP %d version=%s", response.StatusCode, result.Version)
			} else {
				lastErr = requestErr
			}
		} else {
			lastErr = err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
	return lastErr
}
