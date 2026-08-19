package controller

import (
	"os/exec"
	"strings"
	"testing"
)

func TestAgentInstallScriptSyntax(t *testing.T) {
	command := exec.Command("bash", "-n")
	command.Stdin = strings.NewReader(agentInstallScript)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("Agent install script syntax: %v: %s", err, output)
	}
}

func TestAgentInstallScriptCreatesIndependentIdentity(t *testing.T) {
	for _, expected := range []string{"/var/lib/mmwx-guard/machine-id", `"${repair}" = "0"`, "! -s /etc/mmwx-guard/agent.json"} {
		if !strings.Contains(agentInstallScript, expected) {
			t.Fatalf("Agent install script is missing %q", expected)
		}
	}
}
