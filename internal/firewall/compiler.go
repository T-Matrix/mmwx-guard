package firewall

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

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
	b.WriteString("    chain prerouting {\n")
	b.WriteString("        type filter hook prerouting priority raw + 5; policy accept;\n")
	if len(v4) > 0 {
		b.WriteString("        ip saddr @trusted_v4 return comment \"mmwx-guard: trusted IPv4\"\n")
	}
	if len(v6) > 0 {
		b.WriteString("        ip6 saddr @trusted_v6 return comment \"mmwx-guard: trusted IPv6\"\n")
	}
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
	condition := ""
	if len(r.ExemptPorts) == 1 {
		condition = fmt.Sprintf("tcp dport != %d ", r.ExemptPorts[0])
	} else if len(r.ExemptPorts) > 1 {
		ports := make([]string, 0, len(r.ExemptPorts))
		for _, p := range r.ExemptPorts {
			ports = append(ports, strconv.Itoa(int(p)))
		}
		condition = "tcp dport != { " + strings.Join(ports, ", ") + " } "
	}
	base := "        " + condition + "tcp flags & (fin | syn | rst | ack) == syn "
	fmt.Fprintf(b, "%sip saddr 0.0.0.0/0 limit rate over %d/second burst %d packets update @offenders_v4 { ip saddr timeout 10m counter } counter drop comment \"mmwx-guard: global IPv4\"\n", base, r.Rate, r.Burst)
	fmt.Fprintf(b, "%sip6 saddr ::/0 limit rate over %d/second burst %d packets update @offenders_v6 { ip6 saddr timeout 10m counter } counter drop comment \"mmwx-guard: global IPv6\"\n", base, r.Rate, r.Burst)
}
