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

type Policy struct {
	ID             int64      `json:"id"`
	Revision       int64      `json:"revision"`
	Name           string     `json:"name"`
	Enabled        bool       `json:"enabled"`
	Ports          []PortRule `json:"ports"`
	Global         GlobalRule `json:"global"`
	TrustedCIDRs   []string   `json:"trusted_cidrs"`
	UpdatedAt      string     `json:"updated_at,omitempty"`
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
