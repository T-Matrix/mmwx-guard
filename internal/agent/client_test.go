package agent

import (
	"testing"
	"time"

	"github.com/T-Matrix/mmwx-guard/internal/protocol"
)

func TestValidateControllerURL(t *testing.T) {
	for _, value := range []string{"https://guard.example.com", "http://localhost:9080", "http://127.0.0.1:9080"} {
		if err := validateControllerURL(value); err != nil {
			t.Fatalf("valid URL %q rejected: %v", value, err)
		}
	}
	for _, value := range []string{"http://guard.example.com", "https://user:pass@guard.example.com", "https://guard.example.com/path", "https://guard.example.com?secret=value", "ftp://guard.example.com"} {
		if err := validateControllerURL(value); err == nil {
			t.Fatalf("unsafe URL %q accepted", value)
		}
	}
}

func TestAcceptCommandRejectsReplay(t *testing.T) {
	client := &Client{seen: make(map[string]time.Time)}
	message, err := protocol.NewMessage(protocol.TypeApplyPolicy, "0123456789abcdef", map[string]bool{"ok": true})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.acceptCommand(message); err != nil {
		t.Fatalf("first command rejected: %v", err)
	}
	if err := client.acceptCommand(message); err == nil {
		t.Fatal("replayed command accepted")
	}
}
