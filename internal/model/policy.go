package model

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"unicode/utf8"
)

type PortRule struct {
	Port           uint16 `json:"port"`
	PerIPRate      int    `json:"per_ip_rate"`
	PerIPBurst     int    `json:"per_ip_burst"`
	AggregateRate  int    `json:"aggregate_rate"`
	AggregateBurst int    `json:"aggregate_burst"`
	Enabled        bool   `json:"enabled"`
}

type GlobalRule struct {
	Rate        int      `json:"rate"`
	Burst       int      `json:"burst"`
	ExemptPorts []uint16 `json:"exempt_ports"`
	Enabled     bool     `json:"enabled"`
}

type AdaptiveRule struct {
	Enabled                 bool `json:"enabled"`
	TriggerConntrackPercent int  `json:"trigger_conntrack_percent"`
	RecoverConntrackPercent int  `json:"recover_conntrack_percent"`
	TriggerConnections      int  `json:"trigger_connections"`
	RecoverConnections      int  `json:"recover_connections"`
	TriggerSYN              int  `json:"trigger_syn"`
	RecoverSYN              int  `json:"recover_syn"`
	EmergencyRate           int  `json:"emergency_rate"`
	EmergencyBurst          int  `json:"emergency_burst"`
}

type Policy struct {
	ID           int64        `json:"id"`
	Revision     int64        `json:"revision"`
	Name         string       `json:"name"`
	Enabled      bool         `json:"enabled"`
	Ports        []PortRule   `json:"ports"`
	Global       GlobalRule   `json:"global"`
	Adaptive     AdaptiveRule `json:"adaptive"`
	TrustedCIDRs []string     `json:"trusted_cidrs"`
	UpdatedAt    string       `json:"updated_at,omitempty"`
}

func DefaultPolicy() Policy {
	return Policy{
		Name:     "Default elastic protection",
		Revision: 1,
		Enabled:  true,
		Ports: []PortRule{{
			Port: 15542, PerIPRate: 100, PerIPBurst: 500,
			AggregateRate: 300, AggregateBurst: 1500, Enabled: true,
		}},
		Global: GlobalRule{
			Rate: 800, Burst: 4000, ExemptPorts: []uint16{22, 48357}, Enabled: true,
		},
		Adaptive: defaultAdaptiveRule(),
	}
}

func defaultAdaptiveRule() AdaptiveRule {
	return AdaptiveRule{
		TriggerConntrackPercent: 70,
		RecoverConntrackPercent: 45,
		TriggerConnections:      8000,
		RecoverConnections:      5000,
		TriggerSYN:              400,
		RecoverSYN:              100,
		EmergencyRate:           200,
		EmergencyBurst:          600,
	}
}

func (p *Policy) Normalize() {
	p.Name = strings.TrimSpace(p.Name)
	if p.Revision < 1 {
		p.Revision = 1
	}
	if p.Ports == nil {
		p.Ports = []PortRule{}
	}
	if p.TrustedCIDRs == nil {
		p.TrustedCIDRs = []string{}
	}
	if p.Global.ExemptPorts == nil {
		p.Global.ExemptPorts = []uint16{}
	}
	defaults := defaultAdaptiveRule()
	if p.Adaptive.TriggerConntrackPercent == 0 {
		p.Adaptive.TriggerConntrackPercent = defaults.TriggerConntrackPercent
	}
	if p.Adaptive.RecoverConntrackPercent == 0 {
		p.Adaptive.RecoverConntrackPercent = defaults.RecoverConntrackPercent
	}
	if p.Adaptive.TriggerConnections == 0 {
		p.Adaptive.TriggerConnections = defaults.TriggerConnections
	}
	if p.Adaptive.RecoverConnections == 0 {
		p.Adaptive.RecoverConnections = defaults.RecoverConnections
	}
	if p.Adaptive.TriggerSYN == 0 {
		p.Adaptive.TriggerSYN = defaults.TriggerSYN
	}
	if p.Adaptive.RecoverSYN == 0 {
		p.Adaptive.RecoverSYN = defaults.RecoverSYN
	}
	if p.Adaptive.EmergencyRate == 0 {
		p.Adaptive.EmergencyRate = defaults.EmergencyRate
	}
	if p.Adaptive.EmergencyBurst == 0 {
		p.Adaptive.EmergencyBurst = defaults.EmergencyBurst
	}
	sort.Slice(p.Ports, func(i, j int) bool { return p.Ports[i].Port < p.Ports[j].Port })
	sort.Slice(p.Global.ExemptPorts, func(i, j int) bool { return p.Global.ExemptPorts[i] < p.Global.ExemptPorts[j] })
	for i := range p.TrustedCIDRs {
		p.TrustedCIDRs[i] = strings.TrimSpace(p.TrustedCIDRs[i])
	}
}

func (p Policy) Validate() error {
	if count := utf8.RuneCountInString(strings.TrimSpace(p.Name)); count < 1 || count > 80 {
		return errors.New("policy name must contain 1 to 80 characters")
	}
	if len(p.Ports) > 64 {
		return errors.New("a policy can protect at most 64 ports")
	}
	seen := make(map[uint16]bool, len(p.Ports))
	for _, rule := range p.Ports {
		if rule.Port == 0 {
			return errors.New("port must be between 1 and 65535")
		}
		if seen[rule.Port] {
			return fmt.Errorf("duplicate port %d", rule.Port)
		}
		seen[rule.Port] = true
		if !rule.Enabled {
			continue
		}
		if err := validateRate("per-IP", rule.PerIPRate, rule.PerIPBurst); err != nil {
			return fmt.Errorf("port %d: %w", rule.Port, err)
		}
		if err := validateRate("aggregate", rule.AggregateRate, rule.AggregateBurst); err != nil {
			return fmt.Errorf("port %d: %w", rule.Port, err)
		}
		if rule.AggregateRate < rule.PerIPRate {
			return fmt.Errorf("port %d: aggregate rate cannot be lower than per-IP rate", rule.Port)
		}
	}
	if p.Global.Enabled {
		if err := validateRate("global", p.Global.Rate, p.Global.Burst); err != nil {
			return err
		}
	}
	if p.Adaptive.Enabled {
		if p.Adaptive.TriggerConntrackPercent < 20 || p.Adaptive.TriggerConntrackPercent > 99 {
			return errors.New("adaptive conntrack trigger must be between 20 and 99 percent")
		}
		if p.Adaptive.RecoverConntrackPercent < 5 || p.Adaptive.RecoverConntrackPercent >= p.Adaptive.TriggerConntrackPercent {
			return errors.New("adaptive conntrack recovery must be lower than the trigger")
		}
		if p.Adaptive.TriggerConnections < 100 || p.Adaptive.TriggerConnections > 100_000_000 || p.Adaptive.RecoverConnections < 1 || p.Adaptive.RecoverConnections >= p.Adaptive.TriggerConnections {
			return errors.New("adaptive connection recovery must be lower than the trigger")
		}
		if p.Adaptive.TriggerSYN < 10 || p.Adaptive.TriggerSYN > 10_000_000 || p.Adaptive.RecoverSYN < 1 || p.Adaptive.RecoverSYN >= p.Adaptive.TriggerSYN {
			return errors.New("adaptive SYN recovery must be lower than the trigger")
		}
		if err := validateRate("adaptive emergency", p.Adaptive.EmergencyRate, p.Adaptive.EmergencyBurst); err != nil {
			return err
		}
	}
	if len(p.Global.ExemptPorts) > 256 {
		return errors.New("a policy can exempt at most 256 ports")
	}
	if len(p.TrustedCIDRs) > 128 {
		return errors.New("a policy can trust at most 128 IP ranges")
	}
	for _, raw := range p.TrustedCIDRs {
		if len(raw) > 128 {
			return errors.New("trusted IP or CIDR is too long")
		}
		if raw == "" {
			continue
		}
		if _, err := netip.ParsePrefix(raw); err != nil {
			if addr, addrErr := netip.ParseAddr(raw); addrErr != nil {
				return fmt.Errorf("invalid trusted IP or CIDR %q", raw)
			} else if addr.Is4() {
				raw += "/32"
			} else {
				raw += "/128"
			}
			if _, err = netip.ParsePrefix(raw); err != nil {
				return fmt.Errorf("invalid trusted IP or CIDR %q", raw)
			}
		}
	}
	return nil
}

func validateRate(label string, rate, burst int) error {
	if rate < 1 || rate > 1000000 {
		return fmt.Errorf("%s rate must be between 1 and 1000000 per second", label)
	}
	if burst < rate || burst > 10000000 {
		return fmt.Errorf("%s burst must be at least the rate and no more than 10000000", label)
	}
	return nil
}
