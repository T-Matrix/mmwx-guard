package protocol

import (
	"testing"
	"time"
)

func TestValidateCommandFreshness(t *testing.T) {
	now := time.Date(2026, 8, 19, 0, 0, 0, 0, time.UTC)
	valid := Message{Type: TypeApplyPolicy, RequestID: "0123456789abcdef", SentAt: now.Add(-time.Minute).Format(time.RFC3339Nano)}
	if err := ValidateCommand(valid, now); err != nil {
		t.Fatalf("valid command rejected: %v", err)
	}
	stale := valid
	stale.SentAt = now.Add(-3 * time.Minute).Format(time.RFC3339Nano)
	if err := ValidateCommand(stale, now); err == nil {
		t.Fatal("stale command accepted")
	}
	future := valid
	future.SentAt = now.Add(time.Minute).Format(time.RFC3339Nano)
	if err := ValidateCommand(future, now); err == nil {
		t.Fatal("future command accepted")
	}
	shortID := valid
	shortID.RequestID = "short"
	if err := ValidateCommand(shortID, now); err == nil {
		t.Fatal("short request ID accepted")
	}
}

func TestValidateHelloBoundsMetadata(t *testing.T) {
	if err := ValidateHello(Hello{MachineID: "machine-1", OS: "linux", Arch: "amd64", Version: "v1.0.0"}); err != nil {
		t.Fatalf("valid hello rejected: %v", err)
	}
	if err := ValidateHello(Hello{MachineID: ""}); err == nil {
		t.Fatal("empty machine ID accepted")
	}
}

func TestValidateHelloRejectsMalformedControllerFingerprint(t *testing.T) {
	hello := Hello{
		MachineID: "machine-1", Challenge: EncodeKey(make([]byte, 32)),
		AgentEphemeralPublicKey: EncodeKey(make([]byte, 32)), ControllerKeyFingerprint: "zz" + string(make([]byte, 62)),
	}
	if err := ValidateHello(hello); err == nil {
		t.Fatal("malformed controller fingerprint was accepted")
	}
}

func TestValidateAddressReport(t *testing.T) {
	for _, report := range []AddressReport{
		{IPv4: "104.251.231.10"},
		{IPv6: "2605:52c0:1:1313:8022:3ff:fe12:4fce"},
		{IPv4: "104.251.231.10", IPv6: "2605:52c0:1:1313:8022:3ff:fe12:4fce"},
	} {
		if err := ValidateAddressReport(report); err != nil {
			t.Fatalf("valid address report %#v rejected: %v", report, err)
		}
	}
	for _, report := range []AddressReport{
		{},
		{IPv4: "127.0.0.1"},
		{IPv4: "2605:52c0::1"},
		{IPv6: "104.251.231.10"},
		{IPv6: "fd00::1"},
	} {
		if err := ValidateAddressReport(report); err == nil {
			t.Fatalf("invalid address report %#v accepted", report)
		}
	}
}
