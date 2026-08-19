package telemetry

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/T-Matrix/mmwx-guard/internal/firewall"
	"github.com/T-Matrix/mmwx-guard/internal/model"
)

type Collector struct {
	firewall *firewall.Manager
}

func NewCollector(manager *firewall.Manager) *Collector {
	return &Collector{firewall: manager}
}

func (c *Collector) Collect(ctx context.Context) model.Telemetry {
	t := model.Telemetry{CollectedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	t.Load1, t.Load5 = loadAverage()
	t.MemoryUsed, t.MemoryTotal = memoryUsage()
	t.Conntrack = readUint("/proc/sys/net/netfilter/nf_conntrack_count")
	t.ConntrackMax = readUint("/proc/sys/net/netfilter/nf_conntrack_max")
	t.Sockets, t.TopSources = socketStats(ctx)
	t.Protected, t.DroppedTotal = nftStats(ctx)
	if policy, err := c.firewall.CurrentPolicy(); err == nil {
		t.PolicyRevision = policy.Revision
	}
	mergeOffenderDrops(ctx, &t.TopSources)
	if len(t.TopSources) > 20 {
		t.TopSources = t.TopSources[:20]
	}
	return t
}

func loadAverage() (float64, float64) {
	raw, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return 0, 0
	}
	fields := strings.Fields(string(raw))
	if len(fields) < 2 {
		return 0, 0
	}
	one, _ := strconv.ParseFloat(fields[0], 64)
	five, _ := strconv.ParseFloat(fields[1], 64)
	return one, five
}

func memoryUsage() (uint64, uint64) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, 0
	}
	defer f.Close()
	var total, available uint64
	s := bufio.NewScanner(f)
	for s.Scan() {
		fields := strings.Fields(s.Text())
		if len(fields) < 2 {
			continue
		}
		value, _ := strconv.ParseUint(fields[1], 10, 64)
		switch strings.TrimSuffix(fields[0], ":") {
		case "MemTotal":
			total = value * 1024
		case "MemAvailable":
			available = value * 1024
		}
	}
	if total < available {
		return 0, total
	}
	return total - available, total
}

func readUint(path string) uint64 {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	value, _ := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64)
	return value
}

func socketStats(ctx context.Context) (model.SocketStats, []model.SourceCount) {
	if runtime.GOOS != "linux" {
		return model.SocketStats{}, nil
	}
	out, err := exec.CommandContext(ctx, "ss", "-tanH").Output()
	if err != nil {
		return model.SocketStats{}, nil
	}
	var stats model.SocketStats
	sources := map[string]int{}
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 5 {
			continue
		}
		stats.Total++
		switch fields[0] {
		case "ESTAB":
			stats.Established++
		case "SYN-RECV":
			stats.SynRecv++
		case "SYN-SENT":
			stats.SynSent++
		case "TIME-WAIT":
			stats.TimeWait++
		}
		if fields[0] == "LISTEN" {
			continue
		}
		if ip := hostPart(fields[4]); ip != "" && ip != "*" {
			sources[ip]++
		}
	}
	top := make([]model.SourceCount, 0, len(sources))
	for ip, count := range sources {
		top = append(top, model.SourceCount{IP: ip, Connections: count})
	}
	sort.Slice(top, func(i, j int) bool { return top[i].Connections > top[j].Connections })
	return stats, top
}

func hostPart(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if strings.HasPrefix(value, "[::ffff:") {
		value = strings.TrimPrefix(value, "[::ffff:")
		if idx := strings.LastIndex(value, "]:"); idx >= 0 {
			return value[:idx]
		}
	}
	if host, _, err := net.SplitHostPort(value); err == nil {
		return strings.Trim(host, "[]")
	}
	if idx := strings.LastIndex(value, ":"); idx > 0 {
		return strings.Trim(value[:idx], "[]")
	}
	return value
}

var counterPattern = regexp.MustCompile(`counter packets ([0-9]+) bytes`)

func nftStats(ctx context.Context) (bool, uint64) {
	if runtime.GOOS != "linux" {
		return false, 0
	}
	out, err := exec.CommandContext(ctx, "nft", "list", "chain", "inet", firewall.TableName, "prerouting").CombinedOutput()
	if err != nil {
		return false, 0
	}
	var total uint64
	for _, match := range counterPattern.FindAllStringSubmatch(string(out), -1) {
		value, _ := strconv.ParseUint(match[1], 10, 64)
		total += value
	}
	return true, total
}

var offenderPattern = regexp.MustCompile(`([0-9A-Fa-f:.]+).*?counter packets ([0-9]+) bytes`)

func mergeOffenderDrops(ctx context.Context, top *[]model.SourceCount) {
	if runtime.GOOS != "linux" {
		return
	}
	drops := map[string]uint64{}
	for _, setName := range []string{"offenders_v4", "offenders_v6"} {
		out, err := exec.CommandContext(ctx, "nft", "list", "set", "inet", firewall.TableName, setName).CombinedOutput()
		if err != nil {
			continue
		}
		for _, match := range offenderPattern.FindAllStringSubmatch(string(out), -1) {
			value, _ := strconv.ParseUint(match[2], 10, 64)
			drops[match[1]] += value
		}
	}
	indices := map[string]int{}
	for i := range *top {
		indices[(*top)[i].IP] = i
	}
	for ip, count := range drops {
		if i, ok := indices[ip]; ok {
			(*top)[i].Dropped = count
		} else {
			*top = append(*top, model.SourceCount{IP: ip, Dropped: count})
		}
	}
	sort.Slice(*top, func(i, j int) bool {
		left := uint64((*top)[i].Connections) + (*top)[i].Dropped
		right := uint64((*top)[j].Connections) + (*top)[j].Dropped
		return left > right
	})
}

func MachineID() string {
	for _, path := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		if raw, err := os.ReadFile(path); err == nil && strings.TrimSpace(string(raw)) != "" {
			return strings.TrimSpace(string(raw))
		}
	}
	hostname, _ := os.Hostname()
	return fmt.Sprintf("%s-%s-%s", hostname, runtime.GOOS, runtime.GOARCH)
}
