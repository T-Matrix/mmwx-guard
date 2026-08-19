package updater

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	requestFilename = "request.json"
	statusFilename  = "status.json"
)

type Request struct {
	Version      string `json:"version"`
	Repository   string `json:"repository"`
	RequestedAt  string `json:"requested_at"`
	CurrentBuild string `json:"current_build"`
}

type Status struct {
	State     string `json:"state"`
	Version   string `json:"version,omitempty"`
	Message   string `json:"message"`
	UpdatedAt string `json:"updated_at"`
}

type Info struct {
	CurrentVersion  string `json:"current_version"`
	LatestVersion   string `json:"latest_version"`
	UpdateAvailable bool   `json:"update_available"`
	PublishedAt     string `json:"published_at,omitempty"`
	ReleaseURL      string `json:"release_url"`
	Repository      string `json:"repository"`
	Status          Status `json:"status"`
}

type Manager struct {
	Repository     string
	CurrentVersion string
	UpdateDir      string
	Client         ReleaseClient
}

func NewManager(repository, currentVersion, updateDir string) *Manager {
	if repository == "" {
		repository = DefaultRepository
	}
	return &Manager{
		Repository:     repository,
		CurrentVersion: currentVersion,
		UpdateDir:      updateDir,
		Client:         ReleaseClient{Repository: repository},
	}
}

func (m *Manager) Check(ctx context.Context) (Info, error) {
	manifest, err := m.Client.Latest(ctx)
	if err != nil {
		return Info{}, err
	}
	return Info{
		CurrentVersion:  m.CurrentVersion,
		LatestVersion:   manifest.Version,
		UpdateAvailable: IsNewer(manifest.Version, m.CurrentVersion),
		PublishedAt:     manifest.PublishedAt,
		ReleaseURL:      "https://github.com/" + m.Repository + "/releases/tag/" + manifest.Version,
		Repository:      m.Repository,
		Status:          m.ReadStatus(),
	}, nil
}

func (m *Manager) RequestUpdate(ctx context.Context, version string) (Status, error) {
	currentStatus := m.ReadStatus()
	switch currentStatus.State {
	case "queued", "downloading", "installing", "restarting":
		return Status{}, fmt.Errorf("an update to %s is already in progress", currentStatus.Version)
	}
	if version == "" {
		latest, err := m.Client.Latest(ctx)
		if err != nil {
			return Status{}, err
		}
		version = latest.Version
	}
	manifest, err := m.Client.Version(ctx, version)
	if err != nil {
		return Status{}, err
	}
	if manifest.Version != version {
		return Status{}, errors.New("release manifest version does not match request")
	}
	if !IsNewer(version, m.CurrentVersion) {
		return Status{}, fmt.Errorf("version %s is not newer than %s", version, m.CurrentVersion)
	}
	if err := os.MkdirAll(m.UpdateDir, 0700); err != nil {
		return Status{}, fmt.Errorf("create update directory: %w", err)
	}
	if err := os.Chmod(m.UpdateDir, 0700); err != nil {
		return Status{}, fmt.Errorf("secure update directory: %w", err)
	}
	request := Request{
		Version:      version,
		Repository:   m.Repository,
		RequestedAt:  time.Now().UTC().Format(time.RFC3339Nano),
		CurrentBuild: m.CurrentVersion,
	}
	if err := writeJSONAtomic(filepath.Join(m.UpdateDir, requestFilename), request, 0600); err != nil {
		return Status{}, err
	}
	status := Status{State: "queued", Version: version, Message: "更新请求已提交，系统将自动重启", UpdatedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	if err := writeJSONAtomic(filepath.Join(m.UpdateDir, statusFilename), status, 0600); err != nil {
		return Status{}, err
	}
	return status, nil
}

func (m *Manager) ReadStatus() Status {
	raw, err := os.ReadFile(filepath.Join(m.UpdateDir, statusFilename))
	if err != nil {
		return Status{State: "idle", Message: "尚未执行更新"}
	}
	var status Status
	if json.Unmarshal(raw, &status) != nil || status.State == "" {
		return Status{State: "unknown", Message: "无法读取更新状态"}
	}
	return status
}

func writeJSONAtomic(path string, value any, mode os.FileMode) error {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	dir := filepath.Dir(path)
	temporary, err := os.CreateTemp(dir, ".update-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(mode); err != nil {
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
