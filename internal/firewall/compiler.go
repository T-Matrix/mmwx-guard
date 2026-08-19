package firewall

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/T-Matrix/mmwx-guard/internal/model"
)

const TableName = "mmwx_guard"

func Compile(policy model.Policy) (string, error) {
	policy.Normalize()
	if err := policy.Validate(); err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("table inet " + TableName + " {\n")
	v4, v6 := trustedPrefixes(policy.TrustedCIDRs)
	writeCIDRSet(&b, "trusted_v4", "ipv4_addr", v4)
	writeCIDRSet(&b, "trusted_v6", "ipv6_addr", v6)
	b.WriteString("    set offenders_v4 {\n        type ipv4_addr\n        flags dynamic,timeout\n        timeout 10m\n        counter\n    }\n")
	b.WriteString("    set offenders_v6 {\n        type ipv6_addr\n        flags dynamic,timeout\n        timeout 10m\n        counter\n    }\n")
	b.WriteString("    set manual_bans_v4 {\n        type ipv4_addr\n        flags interval\n        counter\n    }\n")
	b.WriteString("    set manual_bans_v6 {\n        type ipv6_addr\n        flags interval\n        counter\n    }\n")
	b.WriteString("    set temporary_bans_v4 {\n        type ipv4_addr\n        flags timeout\n        counter\n    }\n")
	b.WriteString("    set temporary_bans_v6 {\n        type ipv6_addr\n        flags timeout\n        counter\n    }\n")
	b.WriteString("    chain adaptive_emergency {\n    }\n")
	b.WriteString("    chain prerouting {\n")
	b.WriteString("        type filter hook prerouting priority raw + 5; policy accept;\n")
	if len(v4) > 0 {
		b.WriteString("        ip saddr @trusted_v4 return comment \"mmwx-guard: trusted IPv4\"\n")
	}
	if len(v6) > 0 {
		b.WriteString("        ip6 saddr @trusted_v6 return comment \"mmwx-guard: trusted IPv6\"\n")
	}
	b.WriteString("        ip saddr @manual_bans_v4 counter drop comment \"mmwx-guard: permanent IPv4 ban\"\n")
	b.WriteString("        ip6 saddr @manual_bans_v6 counter drop comment \"mmwx-guard: permanent IPv6 ban\"\n")
	b.WriteString("        ip saddr @temporary_bans_v4 counter drop comment \"mmwx-guard: temporary IPv4 ban\"\n")
	b.WriteString("        ip6 saddr @temporary_bans_v6 counter drop comment \"mmwx-guard: temporary IPv6 ban\"\n")
	b.WriteString("        jump adaptive_emergency comment \"mmwx-guard: adaptive emergency\"\n")
	if policy.Enabled {
		for _, rule := range policy.Ports {
			if rule.Enabled {
				writePortRules(&b, rule)
			}
		}
		if policy.Global.Enabled {
			writeGlobalRule(&b, policy.Global)
		}
	}
	b.WriteString("    }\n}\n")
	return b.String(), nil
}

func SyncBanCommands(bans []model.BanTarget, now time.Time) (string, error) {
	if len(bans) > 2048 {
		return "", fmt.Errorf("too many IP bans: %d", len(bans))
	}
	var b strings.Builder
	for _, setName := range []string{"manual_bans_v4", "manual_bans_v6", "temporary_bans_v4", "temporary_bans_v6"} {
		b.WriteString("flush set inet " + TableName + " " + setName + "\n")
	}
	seen := make(map[netip.Addr]bool, len(bans))
	for _, ban := range bans {
		address, err := netip.ParseAddr(strings.TrimSpace(ban.Address))
		if err != nil || address.IsUnspecified() || address.IsLoopback() || address.IsMulticast() || address.IsLinkLocalUnicast() {
			return "", fmt.Errorf("invalid banned IP address %q", ban.Address)
		}
		address = address.Unmap()
		if seen[address] {
			return "", fmt.Errorf("duplicate banned IP address %q", address)
		}
		seen[address] = true
		family := "v6"
		if address.Is4() {
			family = "v4"
		}
		setName := "manual_bans_" + family
		timeout := ""
		if ban.ExpiresAt != "" {
			expires, parseErr := time.Parse(time.RFC3339Nano, ban.ExpiresAt)
			if parseErr != nil || !expires.After(now) {
				return "", fmt.Errorf("invalid expiry for banned IP %q", address)
			}
			seconds := max(int(expires.Sub(now).Seconds()), 1)
			setName = "temporary_bans_" + family
			timeout = " timeout " + strconv.Itoa(seconds) + "s"
		}
		fmt.Fprintf(&b, "add element inet %s %s { %s%s }\n", TableName, setName, address, timeout)
	}
	return b.String(), nil
}

func AdaptiveEmergencyCommands(policy model.Policy, active bool) (string, error) {
	policy.Normalize()
	if err := policy.Validate(); err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("flush chain inet " + TableName + " adaptive_emergency\n")
	if !active {
		return b.String(), nil
	}
	condition := exemptPortCondition(policy.Global.ExemptPorts)
	base := "add rule inet " + TableName + " adaptive_emergency " + condition + "tcp flags & (fin | syn | rst | ack) == syn "
	fmt.Fprintf(&b, "%sip saddr 0.0.0.0/0 limit rate over %d/second burst %d packets update @offenders_v4 { ip saddr timeout 10m counter } counter drop comment \"mmwx-guard: adaptive emergency IPv4\"\n", base, policy.Adaptive.EmergencyRate, policy.Adaptive.EmergencyBurst)
	fmt.Fprintf(&b, "%sip6 saddr ::/0 limit rate over %d/second burst %d packets update @offenders_v6 { ip6 saddr timeout 10m counter } counter drop comment \"mmwx-guard: adaptive emergency IPv6\"\n", base, policy.Adaptive.EmergencyRate, policy.Adaptive.EmergencyBurst)
	return b.String(), nil
}

func trustedPrefixes(values []string) (v4, v6 []string) {
	for _, raw := range values {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			addr, addrErr := netip.ParseAddr(raw)
			if addrErr != nil {
				continue
			}
			bits := 128
			if addr.Is4() {
				bits = 32
			}
			prefix = netip.PrefixFrom(addr, bits)
		}
		if prefix.Addr().Is4() {
			v4 = append(v4, prefix.String())
		} else {
			v6 = append(v6, prefix.String())
		}
	}
	sort.Strings(v4)
	sort.Strings(v6)
	return v4, v6
}

func writeCIDRSet(b *strings.Builder, name, kind string, values []string) {
	if len(values) == 0 {
		return
	}
	fmt.Fprintf(b, "    set %s {\n        type %s\n        flags interval\n        auto-merge\n        elements = { %s }\n    }\n", name, kind, strings.Join(values, ", "))
}

func writePortRules(b *strings.Builder, r model.PortRule) {
	p := strconv.Itoa(int(r.Port))
	base := "        tcp dport " + p + " tcp flags & (fin | syn | rst | ack) == syn "
	fmt.Fprintf(b, "%sip saddr 0.0.0.0/0 meter port_%s_v4 size 65535 { ip saddr timeout 1m limit rate over %d/second burst %d packets } update @offenders_v4 { ip saddr timeout 10m counter } counter drop comment \"mmwx-guard: port %s per-IP\"\n", base, p, r.PerIPRate, r.PerIPBurst, p)
	fmt.Fprintf(b, "%sip6 saddr ::/0 meter port_%s_v6 size 65535 { ip6 saddr timeout 1m limit rate over %d/second burst %d packets } update @offenders_v6 { ip6 saddr timeout 10m counter } counter drop comment \"mmwx-guard: port %s per-IP\"\n", base, p, r.PerIPRate, r.PerIPBurst, p)
	fmt.Fprintf(b, "%sip saddr 0.0.0.0/0 limit rate over %d/second burst %d packets update @offenders_v4 { ip saddr timeout 10m counter } counter drop comment \"mmwx-guard: port %s aggregate IPv4\"\n", base, r.AggregateRate, r.AggregateBurst, p)
	fmt.Fprintf(b, "%sip6 saddr ::/0 limit rate over %d/second burst %d packets update @offenders_v6 { ip6 saddr timeout 10m counter } counter drop comment \"mmwx-guard: port %s aggregate IPv6\"\n", base, r.AggregateRate, r.AggregateBurst, p)
}

func writeGlobalRule(b *strings.Builder, r model.GlobalRule) {
	condition := exemptPortCondition(r.ExemptPorts)
	base := "        " + condition + "tcp flags & (fin | syn | rst | ack) == syn "
	fmt.Fprintf(b, "%sip saddr 0.0.0.0/0 limit rate over %d/second burst %d packets update @offenders_v4 { ip saddr timeout 10m counter } counter drop comment \"mmwx-guard: global IPv4\"\n", base, r.Rate, r.Burst)
	fmt.Fprintf(b, "%sip6 saddr ::/0 limit rate over %d/second burst %d packets update @offenders_v6 { ip6 saddr timeout 10m counter } counter drop comment \"mmwx-guard: global IPv6\"\n", base, r.Rate, r.Burst)
}

func exemptPortCondition(exemptPorts []uint16) string {
	if len(exemptPorts) == 1 {
		return fmt.Sprintf("tcp dport != %d ", exemptPorts[0])
	}
	if len(exemptPorts) > 1 {
		ports := make([]string, 0, len(exemptPorts))
		for _, port := range exemptPorts {
			ports = append(ports, strconv.Itoa(int(port)))
		}
		return "tcp dport != { " + strings.Join(ports, ", ") + " } "
	}
	return ""
}
