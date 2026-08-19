package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

const turnstileVerifyURL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"

type turnstileVerifier struct {
	siteKey           string
	secret            string
	expectedHostnames map[string]struct{}
	client            *http.Client
	verifyURL         string
}

func turnstileFromEnv() (*turnstileVerifier, error) {
	siteKey := strings.TrimSpace(os.Getenv("TURNSTILE_SITE_KEY"))
	secret := strings.TrimSpace(os.Getenv("TURNSTILE_SECRET"))
	hostnames := strings.TrimSpace(os.Getenv("TURNSTILE_HOSTNAMES"))
	if siteKey == "" && secret == "" && hostnames == "" {
		return nil, nil
	}
	if siteKey == "" || secret == "" || hostnames == "" {
		return nil, errors.New("TURNSTILE_SITE_KEY, TURNSTILE_SECRET, and TURNSTILE_HOSTNAMES must be configured together")
	}
	expected := make(map[string]struct{})
	for _, hostname := range strings.Split(hostnames, ",") {
		hostname = strings.ToLower(strings.TrimSpace(hostname))
		if hostname == "" || strings.ContainsAny(hostname, "/: ") {
			return nil, fmt.Errorf("invalid Turnstile hostname %q", hostname)
		}
		expected[hostname] = struct{}{}
	}
	return &turnstileVerifier{
		siteKey: siteKey, secret: secret, expectedHostnames: expected,
		client: &http.Client{Timeout: 10 * time.Second}, verifyURL: turnstileVerifyURL,
	}, nil
}

func (v *turnstileVerifier) verify(ctx context.Context, token, remoteIP string) error {
	if v == nil {
		return nil
	}
	token = strings.TrimSpace(token)
	if token == "" || len(token) > 2048 {
		return errors.New("Turnstile token is missing or invalid")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, v.verifyURL, strings.NewReader(url.Values{
		"secret": {v.secret}, "response": {token}, "remoteip": {remoteIP},
	}.Encode()))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := v.client.Do(request)
	if err != nil {
		return fmt.Errorf("siteverify request failed: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
		return fmt.Errorf("siteverify returned HTTP %d", response.StatusCode)
	}
	var result struct {
		Success  bool   `json:"success"`
		Action   string `json:"action"`
		Hostname string `json:"hostname"`
	}
	decoder := json.NewDecoder(io.LimitReader(response.Body, 64<<10))
	if err := decoder.Decode(&result); err != nil {
		return fmt.Errorf("decode siteverify response: %w", err)
	}
	_, hostnameAllowed := v.expectedHostnames[strings.ToLower(strings.TrimSpace(result.Hostname))]
	if !result.Success || result.Action != "login" || !hostnameAllowed {
		return errors.New("Turnstile verification rejected")
	}
	return nil
}
