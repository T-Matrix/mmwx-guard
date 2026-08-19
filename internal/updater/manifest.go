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
	"regexp"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultRepository = "T-Matrix/mmwx-guard"
	maxManifestSize   = 1 << 20
	maxAssetSize      = 128 << 20
)

var (
	repositoryPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)
	versionPattern    = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$`)
	sha256Pattern     = regexp.MustCompile(`^[a-f0-9]{64}$`)
)

type Asset struct {
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type Manifest struct {
	Version     string           `json:"version"`
	PublishedAt string           `json:"published_at"`
	Assets      map[string]Asset `json:"assets"`
}

func (m Manifest) Validate() error {
	if !ValidVersion(m.Version) {
		return fmt.Errorf("invalid release version %q", m.Version)
	}
	if len(m.Assets) == 0 {
		return errors.New("release manifest contains no assets")
	}
	for name, asset := range m.Assets {
		if !validAssetName(name) {
			return fmt.Errorf("invalid asset name %q", name)
		}
		if !sha256Pattern.MatchString(strings.ToLower(asset.SHA256)) {
			return fmt.Errorf("invalid SHA-256 for %s", name)
		}
		if asset.Size < 1 || asset.Size > maxAssetSize {
			return fmt.Errorf("invalid size for %s", name)
		}
	}
	return nil
}

func ValidRepository(repository string) bool {
	return repositoryPattern.MatchString(repository)
}

func ValidVersion(version string) bool {
	return versionPattern.MatchString(version)
}

func IsNewer(latest, current string) bool {
	if !ValidVersion(latest) {
		return false
	}
	if !ValidVersion(current) {
		return latest != current
	}
	latestParts, latestPre := versionParts(latest)
	currentParts, currentPre := versionParts(current)
	for i := range latestParts {
		if latestParts[i] != currentParts[i] {
			return latestParts[i] > currentParts[i]
		}
	}
	if latestPre == currentPre {
		return false
	}
	if latestPre == "" {
		return true
	}
	if currentPre == "" {
		return false
	}
	return latestPre > currentPre
}

func versionParts(version string) ([3]int, string) {
	var result [3]int
	value := strings.TrimPrefix(version, "v")
	core, pre, _ := strings.Cut(value, "-")
	core, _, _ = strings.Cut(core, "+")
	for index, raw := range strings.Split(core, ".") {
		if index >= len(result) {
			break
		}
		result[index], _ = strconv.Atoi(raw)
	}
	return result, pre
}

func validAssetName(name string) bool {
	return name != "" && name == strings.TrimSpace(name) && !strings.ContainsAny(name, `/\\`) && name != "." && name != ".."
}

type ReleaseClient struct {
	Repository string
	HTTPClient *http.Client
}

func (c ReleaseClient) Latest(ctx context.Context) (Manifest, error) {
	return c.fetchManifest(ctx, "latest/download")
}

func (c ReleaseClient) Version(ctx context.Context, version string) (Manifest, error) {
	if !ValidVersion(version) {
		return Manifest{}, fmt.Errorf("invalid version %q", version)
	}
	return c.fetchManifest(ctx, "download/"+version)
}

func (c ReleaseClient) Download(ctx context.Context, version, name string, expected Asset, dst io.Writer) error {
	if !ValidVersion(version) || !validAssetName(name) {
		return errors.New("invalid release asset request")
	}
	response, err := c.do(ctx, releaseBaseURL(c.Repository)+"/download/"+version+"/"+name)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("download %s: HTTP %d", name, response.StatusCode)
	}
	hash := sha256.New()
	written, err := io.Copy(io.MultiWriter(dst, hash), io.LimitReader(response.Body, maxAssetSize+1))
	if err != nil {
		return fmt.Errorf("download %s: %w", name, err)
	}
	if written != expected.Size {
		return fmt.Errorf("download %s: size mismatch: got %d, want %d", name, written, expected.Size)
	}
	actual := hex.EncodeToString(hash.Sum(nil))
	if actual != strings.ToLower(expected.SHA256) {
		return fmt.Errorf("download %s: SHA-256 mismatch", name)
	}
	return nil
}

func (c ReleaseClient) fetchManifest(ctx context.Context, suffix string) (Manifest, error) {
	response, err := c.do(ctx, releaseBaseURL(c.Repository)+"/"+suffix+"/manifest.json")
	if err != nil {
		return Manifest{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return Manifest{}, fmt.Errorf("fetch release manifest: HTTP %d", response.StatusCode)
	}
	var manifest Manifest
	decoder := json.NewDecoder(io.LimitReader(response.Body, maxManifestSize))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return Manifest{}, fmt.Errorf("decode release manifest: %w", err)
	}
	if err := manifest.Validate(); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func (c ReleaseClient) do(ctx context.Context, url string) (*http.Response, error) {
	if !ValidRepository(c.Repository) {
		return nil, fmt.Errorf("invalid release repository %q", c.Repository)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/octet-stream")
	request.Header.Set("User-Agent", "mmwx-guard-updater")
	client := c.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 2 * time.Minute}
	}
	return client.Do(request)
}

func releaseBaseURL(repository string) string {
	return "https://github.com/" + repository + "/releases"
}
