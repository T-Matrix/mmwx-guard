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
