package controller

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/T-Matrix/mmwx-guard/internal/model"
	"github.com/T-Matrix/mmwx-guard/internal/store"
)

func TestDiagnosticBundleIsScopedAndRedactsSecrets(t *testing.T) {
	database, err := store.Open(filepath.Join(t.TempDir(), "guard.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	ctx := context.Background()
	if err := database.CreateAgent(ctx, store.NewAgent{ID: "agent-one", Name: "Agent One", MachineID: "machine-one", SecretHash: "stored-secret-hash", OS: "linux", Arch: "amd64", Version: "v-test", IPAddress: "203.0.113.8"}); err != nil {
		t.Fatal(err)
	}
	if err := database.SetAgentPublicAddresses(ctx, "agent-one", "203.0.113.8", ""); err != nil {
		t.Fatal(err)
	}
	telemetry := model.Telemetry{
		CollectedAt: time.Now().UTC().Format(time.RFC3339Nano), MemoryUsed: 1, MemoryTotal: 2,
		Sockets:    model.SocketStats{Total: 1, Established: 1},
		PortHealth: []model.PortHealth{{Key: "mmw:test:443", Kind: "mmw", Port: 443, Status: "healthy", LatencyMS: 2, CheckedAt: time.Now().UTC().Format(time.RFC3339Nano)}},
	}
	if err := database.UpdateTelemetry(ctx, "agent-one", telemetry); err != nil {
		t.Fatal(err)
	}
	secret := "very-sensitive-token-value-123456"
	if err := database.AddEvent(ctx, "error", "test", "agent-one", "request failed Authorization: Bearer "+secret+" --token '"+secret+"'", map[string]string{"token": secret}); err != nil {
		t.Fatal(err)
	}
	if err := database.AddEvent(ctx, "info", "other", "agent-two", "must-not-be-included", nil); err != nil {
		t.Fatal(err)
	}
	server := &Server{store: database, hub: NewHub(), version: "v-test"}
	bundle, err := server.buildDiagnosticBundle(ctx, "agent-one")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(bundle, []byte(secret)) {
		t.Fatal("compressed bundle unexpectedly contains plaintext secret")
	}
	reader, err := zip.NewReader(bytes.NewReader(bundle), int64(len(bundle)))
	if err != nil {
		t.Fatal(err)
	}
	files := make(map[string]string)
	for _, file := range reader.File {
		entry, err := file.Open()
		if err != nil {
			t.Fatal(err)
		}
		raw, err := io.ReadAll(entry)
		entry.Close()
		if err != nil {
			t.Fatal(err)
		}
		files[file.Name] = string(raw)
	}
	for _, name := range []string{"README.txt", "manifest.json", "checks.json", "agent.json", "telemetry.json", "policy.json", "bans.json", "tasks.json", "events.json", "policy-history.json", "metrics-24h.json"} {
		if _, ok := files[name]; !ok {
			t.Fatalf("diagnostic bundle is missing %s", name)
		}
	}
	combined := strings.Join(mapValues(files), "\n")
	if strings.Contains(combined, secret) || strings.Contains(combined, "stored-secret-hash") {
		t.Fatal("diagnostic bundle leaked a secret")
	}
	if !strings.Contains(files["events.json"], "[REDACTED]") {
		t.Fatalf("event secret was not redacted: %s", files["events.json"])
	}
	if strings.Contains(files["events.json"], "must-not-be-included") {
		t.Fatal("diagnostic bundle included another Agent's event")
	}
}

func TestDiagnosticDownloadRequiresAdminAndReturnsPrivateZIP(t *testing.T) {
	database, err := store.Open(filepath.Join(t.TempDir(), "guard.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	ctx := context.Background()
	if err := database.CreateAgent(ctx, store.NewAgent{ID: "download-agent", Name: "Download Agent", MachineID: "download-machine", SecretHash: "hash"}); err != nil {
		t.Fatal(err)
	}
	if err := database.CreateAdmin(ctx, "admin", "unused-hash"); err != nil {
		t.Fatal(err)
	}
	adminID, _, err := database.AdminPasswordHash(ctx, "admin")
	if err != nil {
		t.Fatal(err)
	}
	token := "diagnostic-test-session"
	if err := database.CreateSession(ctx, hashToken(token), adminID, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	server := &Server{store: database, hub: NewHub(), version: "v-test"}
	handler := server.Handler()

	unauthorized := httptest.NewRecorder()
	handler.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "/api/admin/agents/download-agent/diagnostics", nil))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized diagnostic download status = %d", unauthorized.Code)
	}

	request := httptest.NewRequest(http.MethodGet, "/api/admin/agents/download-agent/diagnostics", nil)
	request.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Header().Get("Content-Type") != "application/zip" || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("diagnostic response = %d, type %q, cache %q", response.Code, response.Header().Get("Content-Type"), response.Header().Get("Cache-Control"))
	}
	if disposition := response.Header().Get("Content-Disposition"); !strings.Contains(disposition, "attachment;") || !strings.Contains(disposition, ".zip") {
		t.Fatalf("diagnostic Content-Disposition = %q", disposition)
	}
	if _, err := zip.NewReader(bytes.NewReader(response.Body.Bytes()), int64(response.Body.Len())); err != nil {
		t.Fatalf("download is not a valid ZIP: %v", err)
	}

	missingRequest := httptest.NewRequest(http.MethodGet, "/api/admin/agents/missing/diagnostics", nil)
	missingRequest.AddCookie(&http.Cookie{Name: sessionCookie, Value: token})
	missingResponse := httptest.NewRecorder()
	handler.ServeHTTP(missingResponse, missingRequest)
	if missingResponse.Code != http.StatusNotFound {
		t.Fatalf("missing Agent diagnostic status = %d", missingResponse.Code)
	}
}

func mapValues(values map[string]string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, value)
	}
	return out
}
