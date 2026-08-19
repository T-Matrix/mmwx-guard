package firewall

import (
	"strings"
	"testing"

	"github.com/T-Matrix/mmwx-guard/internal/model"
)

func TestCompileDefaultPolicy(t *testing.T) {
	rules, err := Compile(model.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"table inet mmwx_guard",
		"tcp dport 15542",
		"limit rate over 100/second burst 500 packets",
		"ip saddr 0.0.0.0/0 limit rate over 300/second",
		"ip6 saddr ::/0 limit rate over 300/second",
		"tcp dport != { 22, 48357 }",
		"priority raw + 5",
	} {
		if !strings.Contains(rules, want) {
			t.Fatalf("compiled rules do not contain %q:\n%s", want, rules)
		}
	}
}

func TestCompileTrustedCIDRs(t *testing.T) {
	p := model.DefaultPolicy()
	p.TrustedCIDRs = []string{"10.0.0.1", "2001:db8::/32"}
	rules, err := Compile(p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rules, "10.0.0.1/32") || !strings.Contains(rules, "2001:db8::/32") {
		t.Fatalf("trusted prefixes missing:\n%s", rules)
	}
}
