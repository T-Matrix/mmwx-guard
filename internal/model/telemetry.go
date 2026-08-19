package model

import (
	"errors"
	"fmt"
	"math"
	"net/netip"
	"strings"
	"time"
)

const (
	MaxTopSources   = 256
	MaxMMWNodes     = 256
	MaxForwardRules = 512
)

type SourceCount struct {
	IP          string `json:"ip"`
	Connections int    `json:"connections"`
	Dropped     uint64 `json:"dropped,omitempty"`
}

type SocketStats struct {
	Total       int `json:"total"`
	Established int `json:"established"`
	SynRecv     int `json:"syn_recv"`
	SynSent     int `json:"syn_sent"`
	TimeWait    int `json:"time_wait"`
}

type MMWIntegration struct {
	Active         bool              `json:"active"`
	MasterURL      string            `json:"master_url,omitempty"`
	ConnectionMode string            `json:"connection_mode,omitempty"`
	XrayMode       string            `json:"xray_mode,omitempty"`
	Nodes          []MMWNodeListener `json:"nodes"`
}

type MMWNodeListener struct {
	Tag      string `json:"tag,omitempty"`
	Listen   string `json:"listen,omitempty"`
	Port     uint16 `json:"port"`
	Protocol string `json:"protocol"`
	Network  string `json:"network,omitempty"`
	Security string `json:"security,omitempty"`
	Active   bool   `json:"active"`
}

type ForwardRule struct {
	ID         string `json:"id"`
	Protocol   string `json:"protocol"`
	Listen     string `json:"listen"`
	ListenPort uint16 `json:"listen_port"`
	Remote     string `json:"remote"`
	Active     bool   `json:"active"`
}

type ForwardXIntegration struct {
	Active   bool          `json:"active"`
	PanelURL string        `json:"panel_url,omitempty"`
	Rules    []ForwardRule `json:"rules"`
}

type Integrations struct {
	MMW      *MMWIntegration      `json:"mmw,omitempty"`
	ForwardX *ForwardXIntegration `json:"forwardx,omitempty"`
}

type Telemetry struct {
	CollectedAt    string        `json:"collected_at"`
	CPUUsage       float64       `json:"cpu_usage"`
	Load1          float64       `json:"load_1"`
	Load5          float64       `json:"load_5"`
	MemoryUsed     uint64        `json:"memory_used"`
	MemoryTotal    uint64        `json:"memory_total"`
	Sockets        SocketStats   `json:"sockets"`
	Conntrack      uint64        `json:"conntrack"`
	ConntrackMax   uint64        `json:"conntrack_max"`
	DroppedTotal   uint64        `json:"dropped_total"`
	Protected      bool          `json:"protected"`
	PolicyRevision int64         `json:"policy_revision"`
	TopSources     []SourceCount `json:"top_sources"`
	Integrations   Integrations  `json:"integrations"`
}

func (t Telemetry) Validate(now time.Time) error {
	collectedAt, err := time.Parse(time.RFC3339Nano, t.CollectedAt)
	if err != nil {
		return errors.New("telemetry collection timestamp is invalid")
	}
	if collectedAt.After(now.Add(2*time.Minute)) || now.Sub(collectedAt) > 5*time.Minute {
		return errors.New("telemetry collection timestamp is outside the accepted window")
	}
	if !finiteBetween(t.CPUUsage, 0, 100) || !finiteBetween(t.Load1, 0, 1_000_000) || !finiteBetween(t.Load5, 0, 1_000_000) {
		return errors.New("telemetry CPU or load value is invalid")
	}
	if t.MemoryUsed > t.MemoryTotal || t.PolicyRevision < 0 {
		return errors.New("telemetry memory or policy revision is invalid")
	}
	if err := t.Sockets.validate(); err != nil {
		return err
	}
	if t.ConntrackMax > 0 && t.Conntrack > t.ConntrackMax {
		return errors.New("telemetry conntrack count exceeds its maximum")
	}
	if len(t.TopSources) > MaxTopSources {
		return fmt.Errorf("telemetry has too many top sources: %d", len(t.TopSources))
	}
	for _, source := range t.TopSources {
		if _, err := netip.ParseAddr(strings.TrimSpace(source.IP)); err != nil || source.Connections < 0 || source.Connections > t.Sockets.Total {
			return errors.New("telemetry contains an invalid top source")
		}
	}
	return t.Integrations.validate()
}

func (s SocketStats) validate() error {
	const maxSocketCount = 100_000_000
	values := []int{s.Total, s.Established, s.SynRecv, s.SynSent, s.TimeWait}
	for _, value := range values {
		if value < 0 || value > maxSocketCount {
			return errors.New("telemetry socket count is invalid")
		}
	}
	if s.Established > s.Total || s.SynRecv > s.Total || s.SynSent > s.Total || s.TimeWait > s.Total {
		return errors.New("telemetry socket state exceeds total sockets")
	}
	return nil
}

func (i Integrations) validate() error {
	if i.MMW != nil {
		if !shortString(i.MMW.MasterURL, 2048) || !shortString(i.MMW.ConnectionMode, 128) || !shortString(i.MMW.XrayMode, 128) || len(i.MMW.Nodes) > MaxMMWNodes {
			return errors.New("telemetry contains invalid MMW integration metadata")
		}
		for _, node := range i.MMW.Nodes {
			if node.Port == 0 || !shortString(node.Tag, 512) || !shortString(node.Listen, 512) || !shortString(node.Protocol, 128) || !shortString(node.Network, 128) || !shortString(node.Security, 128) {
				return errors.New("telemetry contains an invalid MMW node")
			}
		}
	}
	if i.ForwardX != nil {
		if !shortString(i.ForwardX.PanelURL, 2048) || len(i.ForwardX.Rules) > MaxForwardRules {
			return errors.New("telemetry contains invalid ForwardX integration metadata")
		}
		for _, rule := range i.ForwardX.Rules {
			if rule.ListenPort == 0 || !shortString(rule.ID, 512) || !shortString(rule.Protocol, 128) || !shortString(rule.Listen, 512) || !shortString(rule.Remote, 512) {
				return errors.New("telemetry contains an invalid ForwardX rule")
			}
		}
	}
	return nil
}

func finiteBetween(value, minimum, maximum float64) bool {
	return !math.IsNaN(value) && !math.IsInf(value, 0) && value >= minimum && value <= maximum
}

func shortString(value string, maximum int) bool {
	return len(value) <= maximum
}

type AgentSummary struct {
	ID                       string     `json:"id"`
	Name                     string     `json:"name"`
	Status                   string     `json:"status"`
	IPAddress                string     `json:"ip_address"`
	IPv4Address              string     `json:"ipv4_address,omitempty"`
	IPv6Address              string     `json:"ipv6_address,omitempty"`
	AddressUpdatedAt         string     `json:"address_updated_at,omitempty"`
	OS                       string     `json:"os"`
	Arch                     string     `json:"arch"`
	Version                  string     `json:"version"`
	LastSeen                 string     `json:"last_seen"`
	PolicyID                 int64      `json:"policy_id,omitempty"`
	PolicyName               string     `json:"policy_name,omitempty"`
	PolicyRevision           int64      `json:"policy_revision,omitempty"`
	Telemetry                *Telemetry `json:"telemetry,omitempty"`
	CredentialState          string     `json:"credential_state"`
	CredentialRotatedAt      string     `json:"credential_rotated_at,omitempty"`
	CredentialRevokedAt      string     `json:"credential_revoked_at,omitempty"`
	LastAuthenticatedAt      string     `json:"last_authenticated_at,omitempty"`
	ControllerKeyFingerprint string     `json:"controller_key_fingerprint,omitempty"`
	ControllerVerifiedAt     string     `json:"controller_verified_at,omitempty"`
	SecureChannel            bool       `json:"secure_channel"`
}
