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
	MMWXrayConfigPath  string
	ForwardXConfigPath string
	ForwardXRulesDir   string
	ServiceActive      func(context.Context, string) bool
	ListenerActive     func(context.Context, string, uint16) bool
}

func DefaultOptions() Options {
	return Options{
		MMWConfigPath:      "/etc/mmw-agent/config.yaml",
		MMWXrayConfigPath:  "/usr/local/etc/xray/config.json",
		ForwardXConfigPath: "/etc/forwardx/agent/config.json",
		ForwardXRulesDir:   "/etc/forwardx/realm",
		ServiceActive:      serviceActive,
		ListenerActive:     listenerActive,
	}
}

func Discover(ctx context.Context, options Options) model.Integrations {
	if options.ServiceActive == nil {
		options.ServiceActive = serviceActive
	}
	if options.ListenerActive == nil {
		options.ListenerActive = listenerActive
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
		Nodes:          discoverMMWNodes(ctx, options),
	}
}

func discoverMMWNodes(ctx context.Context, options Options) []model.MMWNodeListener {
	raw, err := os.ReadFile(options.MMWXrayConfigPath)
	if err != nil {
		return []model.MMWNodeListener{}
	}
	var config struct {
		Inbounds []struct {
			Tag            string `json:"tag"`
			Listen         string `json:"listen"`
			Port           uint16 `json:"port"`
			Protocol       string `json:"protocol"`
			StreamSettings struct {
				Network  string `json:"network"`
				Security string `json:"security"`
			} `json:"streamSettings"`
		} `json:"inbounds"`
	}
	if json.Unmarshal(raw, &config) != nil {
		return []model.MMWNodeListener{}
	}
	nodes := make([]model.MMWNodeListener, 0, len(config.Inbounds))
	for _, inbound := range config.Inbounds {
		if inbound.Port == 0 || internalInbound(inbound.Tag) || loopbackOnly(inbound.Listen) {
			continue
		}
		protocol := strings.ToLower(strings.TrimSpace(inbound.Protocol))
		if protocol == "" {
			continue
		}
		network := strings.ToLower(strings.TrimSpace(inbound.StreamSettings.Network))
		if network == "" {
			network = "tcp"
		}
		listen := strings.TrimSpace(inbound.Listen)
		if listen == "" {
			listen = "0.0.0.0"
		}
		nodes = append(nodes, model.MMWNodeListener{
			Tag: strings.TrimSpace(inbound.Tag), Listen: listen, Port: inbound.Port,
			Protocol: protocol, Network: network,
			Security: strings.ToLower(strings.TrimSpace(inbound.StreamSettings.Security)),
			Active:   options.ListenerActive(ctx, listenerNetwork(network), inbound.Port),
		})
	}
	sort.Slice(nodes, func(i, j int) bool {
		if nodes[i].Port == nodes[j].Port {
			return nodes[i].Tag < nodes[j].Tag
		}
		return nodes[i].Port < nodes[j].Port
	})
	return nodes
}

func internalInbound(tag string) bool {
	value := strings.ToLower(strings.TrimSpace(tag))
	for _, marker := range []string{"api", "tunnel"} {
		if value == marker || strings.HasPrefix(value, marker+"-") || strings.HasSuffix(value, "-"+marker) || strings.Contains(value, "-"+marker+"-") {
			return true
		}
	}
	return false
}

func loopbackOnly(listen string) bool {
	value := strings.Trim(strings.TrimSpace(listen), "[]")
	if strings.EqualFold(value, "localhost") {
		return true
	}
	ip := net.ParseIP(value)
	return ip != nil && ip.IsLoopback()
}

func listenerNetwork(network string) string {
	switch strings.ToLower(network) {
	case "kcp", "mkcp", "quic":
		return "udp"
	default:
		return "tcp"
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

func listenerActive(ctx context.Context, network string, port uint16) bool {
	checkCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	flag := "-ltnH"
	if network == "udp" {
		flag = "-lunH"
	}
	out, err := exec.CommandContext(checkCtx, "ss", flag, "sport", "=", ":"+strconv.Itoa(int(port))).Output()
	return err == nil && len(strings.TrimSpace(string(out))) > 0
}
