package updater

import "testing"

func TestIsNewer(t *testing.T) {
	tests := []struct {
		latest, current string
		want            bool
	}{
		{"v0.2.0", "v0.1.2", true},
		{"v0.2.0", "v0.2.0", false},
		{"v0.1.9", "v0.2.0", false},
		{"v1.0.0", "v0.99.99", true},
		{"v1.0.0", "v1.0.0-rc.1", true},
		{"v1.0.0-rc.1", "v1.0.0", false},
		{"v0.2.0", "dev", true},
	}
	for _, test := range tests {
		if got := IsNewer(test.latest, test.current); got != test.want {
			t.Fatalf("IsNewer(%q, %q) = %v, want %v", test.latest, test.current, got, test.want)
		}
	}
}

func TestManifestValidate(t *testing.T) {
	valid := Manifest{Version: "v0.2.0", Assets: map[string]Asset{
		"mmwx-guard-linux-amd64": {SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Size: 42},
	}}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid manifest rejected: %v", err)
	}
	invalid := valid
	invalid.Assets = map[string]Asset{"../binary": valid.Assets["mmwx-guard-linux-amd64"]}
	if err := invalid.Validate(); err == nil {
		t.Fatal("manifest with unsafe asset name was accepted")
	}
}

func TestIsNativeAsset(t *testing.T) {
	if !isNativeAsset("mmwx-guard-agent-linux-amd64", "amd64") {
		t.Fatal("native amd64 Agent was not selected for execution")
	}
	if isNativeAsset("mmwx-guard-agent-linux-arm64", "amd64") {
		t.Fatal("cross-architecture Agent was selected for execution")
	}
}
