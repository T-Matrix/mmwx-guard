package telemetry

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
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
	networkMu    sync.Mutex
	lastNetwork  networkSample
	hasNetwork   bool
	discoveryMu  sync.Mutex
	integrations model.Integrations
	discoveredAt time.Time
	healthMu     sync.Mutex
	portHealth   []model.PortHealth
	healthAt     time.Time
}

func NewCollector(manager *firewall.Manager) *Collector {
	return &Collector{firewall: manager}
}

func (c *Collector) Collect(ctx context.Context) model.Telemetry {
	collectedAt := time.Now()
	t := model.Telemetry{CollectedAt: collectedAt.UTC().Format(time.RFC3339Nano)}
	t.CPUUsage = c.cpuUsage()
	t.Load1, t.Load5 = loadAverage()
	t.MemoryUsed, t.MemoryTotal = memoryUsage()
	t.Network = c.networkUsage(collectedAt)
	t.Conntrack = readUint("/proc/sys/net/netfilter/nf_conntrack_count")
	t.ConntrackMax = readUint("/proc/sys/net/netfilter/nf_conntrack_max")
	t.Sockets, t.TopSources = socketStats(ctx)
	t.Protected, t.DroppedTotal = nftStats(ctx)
	t.Integrations = c.integrationStats(ctx)
	t.PortHealth = c.portHealthStats(ctx, t.Integrations)
	if policy, err := c.firewall.CurrentPolicy(); err == nil {
		t.PolicyRevision = policy.Revision
	}
	mergeOffenderDrops(ctx, &t.TopSources)
	if len(t.TopSources) > model.MaxTopSources {
		t.TopSources = t.TopSources[:model.MaxTopSources]
	}
	return t
}

func (c *Collector) portHealthStats(ctx context.Context, integrations model.Integrations) []model.PortHealth {
	c.healthMu.Lock()
	defer c.healthMu.Unlock()
	if !c.healthAt.IsZero() && time.Since(c.healthAt) < 30*time.Second {
		return append([]model.PortHealth(nil), c.portHealth...)
	}
	probeCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	c.portHealth = probePortHealth(probeCtx, integrations)
	c.healthAt = time.Now()
	return append([]model.PortHealth(nil), c.portHealth...)
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

type networkSample struct {
	receiveBytes  uint64
	transmitBytes uint64
	collectedAt   time.Time
}

func (c *Collector) networkUsage(collectedAt time.Time) model.NetworkStats {
	raw, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return model.NetworkStats{}
	}
	receive, transmit := parseNetworkCounters(string(raw))
	current := networkSample{receiveBytes: receive, transmitBytes: transmit, collectedAt: collectedAt}

	c.networkMu.Lock()
	defer c.networkMu.Unlock()
	previous, hasPrevious := c.lastNetwork, c.hasNetwork
	c.lastNetwork, c.hasNetwork = current, true
	stats := model.NetworkStats{ReceiveBytes: receive, TransmitBytes: transmit}
	if !hasPrevious {
		return stats
	}
	elapsed := current.collectedAt.Sub(previous.collectedAt)
	stats.ReceiveBytesPerSecond = networkRate(previous.receiveBytes, current.receiveBytes, elapsed)
	stats.TransmitBytesPerSecond = networkRate(previous.transmitBytes, current.transmitBytes, elapsed)
	return stats
}

func networkRate(previous, current uint64, elapsed time.Duration) uint64 {
	if current < previous || elapsed <= 0 {
		return 0
	}
	return uint64(float64(current-previous) / elapsed.Seconds())
}

func parseNetworkCounters(raw string) (uint64, uint64) {
	var receive, transmit uint64
	scanner := bufio.NewScanner(strings.NewReader(raw))
	for scanner.Scan() {
		line := scanner.Text()
		name, counters, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		if ignoredNetworkInterface(name) {
			continue
		}
		fields := strings.Fields(counters)
		if len(fields) < 9 {
			continue
		}
		rx, rxErr := strconv.ParseUint(fields[0], 10, 64)
		tx, txErr := strconv.ParseUint(fields[8], 10, 64)
		if rxErr == nil && txErr == nil {
			receive += rx
			transmit += tx
		}
	}
	return receive, transmit
}

func ignoredNetworkInterface(name string) bool {
	if name == "" || name == "lo" {
		return true
	}
	for _, prefix := range []string{"docker", "veth", "br-", "virbr", "cni", "flannel", "kube"} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

func socketStats(ctx context.Context) (model.SocketStats, []model.SourceCount) {
	if runtime.GOOS != "linux" {
		return model.SocketStats{}, nil
	}
	out, err := exec.CommandContext(ctx, "ss", "-tanH").Output()
	if err != nil {
		return model.SocketStats{}, nil
	}
	return parseSocketStats(string(out))
}

func parseSocketStats(raw string) (model.SocketStats, []model.SourceCount) {
	rows := make([][]string, 0)
	listeners := make(map[uint16]bool)
	scanner := bufio.NewScanner(strings.NewReader(raw))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 5 {
			continue
		}
		rows = append(rows, fields)
		if fields[0] == "LISTEN" {
			if port := socketPort(fields[3]); port != 0 {
				listeners[port] = true
			}
		}
	}
	var stats model.SocketStats
	sources := map[string]int{}
	for _, fields := range rows {
		if fields[0] == "LISTEN" || !listeners[socketPort(fields[3])] {
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

func socketPort(value string) uint16 {
	if index := strings.LastIndex(strings.TrimSpace(value), ":"); index >= 0 {
		port, err := strconv.ParseUint(strings.TrimSpace(value[index+1:]), 10, 16)
		if err == nil {
			return uint16(port)
		}
	}
	return 0
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
	out, err := exec.CommandContext(ctx, "nft", "list", "table", "inet", firewall.TableName).CombinedOutput()
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

func mergeOffenderDrops(ctx context.Context, top *[]model.SourceCount) {
	if runtime.GOOS != "linux" {
		return
	}
	drops := map[string]uint64{}
	for _, setName := range []string{"offenders_v4", "offenders_v6", "manual_bans_v4", "manual_bans_v6", "temporary_bans_v4", "temporary_bans_v6"} {
		out, err := exec.CommandContext(ctx, "nft", "-j", "list", "set", "inet", firewall.TableName, setName).CombinedOutput()
		if err != nil {
			continue
		}
		for address, count := range parseNftSetCounters(out) {
			drops[address] += count
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
		return sourceWeight((*top)[i]) > sourceWeight((*top)[j])
	})
}

func parseNftSetCounters(raw []byte) map[string]uint64 {
	var document struct {
		Nftables []struct {
			Set struct {
				Elements []struct {
					Element struct {
						Value   string `json:"val"`
						Counter struct {
							Packets uint64 `json:"packets"`
						} `json:"counter"`
					} `json:"elem"`
				} `json:"elem"`
			} `json:"set"`
		} `json:"nftables"`
	}
	if json.Unmarshal(raw, &document) != nil {
		return nil
	}
	counters := make(map[string]uint64)
	for _, object := range document.Nftables {
		for _, item := range object.Set.Elements {
			address, err := netip.ParseAddr(item.Element.Value)
			if err != nil {
				continue
			}
			counters[address.Unmap().String()] += item.Element.Counter.Packets
		}
	}
	return counters
}

func sourceWeight(source model.SourceCount) uint64 {
	if source.Connections <= 0 {
		return source.Dropped
	}
	connections := uint64(source.Connections) // #nosec G115 -- negative values are rejected above and int always fits uint64.
	if ^uint64(0)-source.Dropped < connections {
		return ^uint64(0)
	}
	return source.Dropped + connections
}

func MachineID() string {
	return machineIDFromFiles([]string{"/var/lib/mmwx-guard/machine-id", "/etc/machine-id", "/var/lib/dbus/machine-id"})
}

func machineIDFromFiles(paths []string) string {
	for _, path := range paths {
		if raw, err := os.ReadFile(path); err == nil && strings.TrimSpace(string(raw)) != "" {
			return strings.TrimSpace(string(raw))
		}
	}
	hostname, _ := os.Hostname()
	return fmt.Sprintf("%s-%s-%s", hostname, runtime.GOOS, runtime.GOARCH)
}
