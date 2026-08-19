package controller

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestTurnstileFromEnvRequiresCompleteConfiguration(t *testing.T) {
	t.Setenv("TURNSTILE_SITE_KEY", "site-key")
	t.Setenv("TURNSTILE_SECRET", "")
	t.Setenv("TURNSTILE_HOSTNAMES", "guard.example.com")
	if _, err := turnstileFromEnv(); err == nil {
		t.Fatal("incomplete Turnstile configuration was accepted")
	}
}

func TestTurnstileVerifyChecksActionAndHostname(t *testing.T) {
	tests := []struct {
		name, response string
		wantErr        bool
	}{
		{name: "valid", response: `{"success":true,"action":"login","hostname":"guard.example.com"}`},
		{name: "wrong action", response: `{"success":true,"action":"signup","hostname":"guard.example.com"}`, wantErr: true},
		{name: "wrong hostname", response: `{"success":true,"action":"login","hostname":"localhost"}`, wantErr: true},
		{name: "challenge rejected", response: `{"success":false,"action":"login","hostname":"guard.example.com"}`, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
					t.Fatalf("unexpected siteverify request")
				}
				if err := r.ParseForm(); err != nil || r.Form.Get("secret") != "secret" || r.Form.Get("response") != "token" || r.Form.Get("remoteip") != "203.0.113.9" {
					t.Fatalf("unexpected siteverify form: %#v, err=%v", r.Form, err)
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(test.response))
			}))
			defer server.Close()
			verifier := &turnstileVerifier{
				secret: "secret", expectedHostnames: map[string]struct{}{"guard.example.com": {}},
				client: &http.Client{Timeout: time.Second}, verifyURL: server.URL,
			}
			err := verifier.verify(context.Background(), "token", "203.0.113.9")
			if (err != nil) != test.wantErr {
				t.Fatalf("verify() error = %v, wantErr=%v", err, test.wantErr)
			}
		})
	}
}

func TestTurnstileVerifyFailsClosedOnUpstreamError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()
	verifier := &turnstileVerifier{secret: "secret", expectedHostnames: map[string]struct{}{"guard.example.com": {}}, client: server.Client(), verifyURL: server.URL}
	if err := verifier.verify(context.Background(), "token", "203.0.113.9"); err == nil {
		t.Fatal("siteverify upstream error was accepted")
	}
}
