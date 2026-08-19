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
	"sync"
	"time"

	"github.com/T-Matrix/mmwx-guard/internal/discovery"
	"github.com/T-Matrix/mmwx-guard/internal/firewall"
	"github.com/T-Matrix/mmwx-guard/internal/model"
)

type Collector struct {
	firewall     *firewall.Manager
	cpuMu        sync.Mutex
	lastCPU      cpuSample
	hasCPU       bool
	discoveryMu  sync.Mutex
	integrations model.Integrations
	discoveredAt time.Time
}

func NewCollector(manager *firewall.Manager) *Collector {
	return &Collector{firewall: manager}
}

func (c *Collector) Collect(ctx context.Context) model.Telemetry {
	t := model.Telemetry{CollectedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	t.CPUUsage = c.cpuUsage()
	t.Load1, t.Load5 = loadAverage()
	t.MemoryUsed, t.MemoryTotal = memoryUsage()
	t.Conntrack = readUint("/proc/sys/net/netfilter/nf_conntrack_count")
	t.ConntrackMax = readUint("/proc/sys/net/netfilter/nf_conntrack_max")
	t.Sockets, t.TopSources = socketStats(ctx)
	t.Protected, t.DroppedTotal = nftStats(ctx)
	t.Integrations = c.integrationStats(ctx)
	if policy, err := c.firewall.CurrentPolicy(); err == nil {
		t.PolicyRevision = policy.Revision
	}
	mergeOffenderDrops(ctx, &t.TopSources)
	if len(t.TopSources) > 20 {
		t.TopSources = t.TopSources[:20]
	}
	return t
}

func (c *Collector) integrationStats(ctx context.Context) model.Integrations {
	c.discoveryMu.Lock()
	defer c.discoveryMu.Unlock()
	if !c.discoveredAt.IsZero() && time.Since(c.discoveredAt) < 30*time.Second {
		return c.integrations
	}
	c.integrations = discovery.Discover(ctx, discovery.DefaultOptions())
	c.discoveredAt = time.Now()
	return c.integrations
}

type cpuSample struct {
	idle  uint64
	total uint64
}

func (c *Collector) cpuUsage() float64 {
	raw, err := os.ReadFile("/proc/stat")
	if err != nil {
		return 0
	}
	current, ok := parseCPUSample(string(raw))
	if !ok {
		return 0
	}

	c.cpuMu.Lock()
	defer c.cpuMu.Unlock()
	previous, hasPrevious := c.lastCPU, c.hasCPU
	c.lastCPU, c.hasCPU = current, true
	if !hasPrevious {
		return 0
	}
	return cpuUsageBetween(previous, current)
}

func cpuUsageBetween(previous, current cpuSample) float64 {
	if current.total <= previous.total || current.idle < previous.idle {
		return 0
	}
	totalDelta := current.total - previous.total
	idleDelta := current.idle - previous.idle
	if idleDelta >= totalDelta {
		return 0
	}
	return float64(totalDelta-idleDelta) * 100 / float64(totalDelta)
}

func parseCPUSample(raw string) (cpuSample, bool) {
	line, _, _ := strings.Cut(raw, "\n")
	fields := strings.Fields(line)
	if len(fields) < 5 || fields[0] != "cpu" {
		return cpuSample{}, false
	}
	values := make([]uint64, 0, 8)
	for _, field := range fields[1:] {
		value, err := strconv.ParseUint(field, 10, 64)
		if err != nil {
			return cpuSample{}, false
		}
		values = append(values, value)
		if len(values) == 8 {
			break
		}
	}
	if len(values) < 4 {
		return cpuSample{}, false
	}
	var total uint64
	for _, value := range values {
		total += value
	}
	idle := values[3]
	if len(values) > 4 {
		idle += values[4]
	}
	return cpuSample{idle: idle, total: total}, total > 0
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
