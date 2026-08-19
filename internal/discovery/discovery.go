package discovery

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"gopkg.in/yaml.v3"

	"github.com/T-Matrix/mmwx-guard/internal/model"
)

type Options struct {
	MMWConfigPath      string
	ForwardXConfigPath string
	ForwardXRulesDir   string
	ServiceActive      func(context.Context, string) bool
}

func DefaultOptions() Options {
	return Options{
		MMWConfigPath:      "/etc/mmw-agent/config.yaml",
		ForwardXConfigPath: "/etc/forwardx/agent/config.json",
		ForwardXRulesDir:   "/etc/forwardx/realm",
		ServiceActive:      serviceActive,
	}
}

func Discover(ctx context.Context, options Options) model.Integrations {
	if options.ServiceActive == nil {
		options.ServiceActive = serviceActive
	}
	return model.Integrations{
		MMW:      discoverMMW(ctx, options),
		ForwardX: discoverForwardX(ctx, options),
	}
}

func discoverMMW(ctx context.Context, options Options) *model.MMWIntegration {
	raw, err := os.ReadFile(options.MMWConfigPath)
	if err != nil {
		return nil
	}
	var config struct {
		MasterURL      string `yaml:"master_url"`
		ConnectionMode string `yaml:"connection_mode"`
		XrayMode       string `yaml:"xray_mode"`
	}
	if yaml.Unmarshal(raw, &config) != nil {
		return nil
	}
	return &model.MMWIntegration{
		Active:         options.ServiceActive(ctx, "mmw-agent.service"),
		MasterURL:      strings.TrimRight(strings.TrimSpace(config.MasterURL), "/"),
		ConnectionMode: strings.TrimSpace(config.ConnectionMode),
		XrayMode:       strings.TrimSpace(config.XrayMode),
	}
}

func discoverForwardX(ctx context.Context, options Options) *model.ForwardXIntegration {
	var config struct {
		PanelURL string `json:"panelUrl"`
	}
	raw, configErr := os.ReadFile(options.ForwardXConfigPath)
	if configErr == nil {
		_ = json.Unmarshal(raw, &config)
	}
	entries, rulesErr := os.ReadDir(options.ForwardXRulesDir)
	if configErr != nil && rulesErr != nil {
		return nil
	}
	integration := &model.ForwardXIntegration{
		Active:   options.ServiceActive(ctx, "forwardx-agent.service"),
		PanelURL: strings.TrimRight(strings.TrimSpace(config.PanelURL), "/"),
		Rules:    []model.ForwardRule{},
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".toml") {
			continue
		}
		path := filepath.Join(options.ForwardXRulesDir, entry.Name())
		integration.Rules = append(integration.Rules, readRealmRules(ctx, path, entry.Name(), options.ServiceActive)...)
	}
	sort.Slice(integration.Rules, func(i, j int) bool {
		if integration.Rules[i].ListenPort == integration.Rules[j].ListenPort {
			return integration.Rules[i].ID < integration.Rules[j].ID
		}
		return integration.Rules[i].ListenPort < integration.Rules[j].ListenPort
	})
	return integration
}

func readRealmRules(ctx context.Context, path, name string, active func(context.Context, string) bool) []model.ForwardRule {
	var config struct {
		Network struct {
			UseUDP bool `toml:"use_udp"`
		} `toml:"network"`
		Endpoints []struct {
			Listen string `toml:"listen"`
			Remote string `toml:"remote"`
		} `toml:"endpoints"`
	}
	if _, err := toml.DecodeFile(path, &config); err != nil {
		return nil
	}
	base := strings.TrimSuffix(name, filepath.Ext(name))
	protocol := realmProtocol(base, config.Network.UseUDP)
	isActive := active(ctx, base+".service")
	rules := make([]model.ForwardRule, 0, len(config.Endpoints))
	for index, endpoint := range config.Endpoints {
		port := addressPort(endpoint.Listen)
		if port == 0 {
			continue
		}
		id := base
		if len(config.Endpoints) > 1 {
			id += "-" + strconv.Itoa(index+1)
		}
		rules = append(rules, model.ForwardRule{
			ID: id, Protocol: protocol, Listen: endpoint.Listen, ListenPort: port,
			Remote: endpoint.Remote, Active: isActive,
		})
	}
	return rules
}

func realmProtocol(name string, useUDP bool) string {
	switch {
	case strings.Contains(name, "-udp-"):
		return "udp"
	case strings.Contains(name, "-both-"):
		return "tcp+udp"
	case strings.Contains(name, "-tcp-"):
		return "tcp"
	case useUDP:
		return "tcp+udp"
	default:
		return "tcp"
	}
}

func addressPort(value string) uint16 {
	_, rawPort, err := net.SplitHostPort(strings.TrimSpace(value))
	if err != nil {
		return 0
	}
	port, err := strconv.ParseUint(rawPort, 10, 16)
	if err != nil || port == 0 {
		return 0
	}
	return uint16(port)
}

func serviceActive(ctx context.Context, unit string) bool {
	checkCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	return exec.CommandContext(checkCtx, "systemctl", "is-active", "--quiet", unit).Run() == nil
}
