package telemetry

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/T-Matrix/mmwx-guard/internal/model"
)

type portProbe struct {
	key       string
	kind      string
	host      string
	port      uint16
	supported bool
}

func probePortHealth(ctx context.Context, integrations model.Integrations) []model.PortHealth {
	probes := portProbes(integrations)
	if len(probes) == 0 {
		return nil
	}
	checkedAt := time.Now().UTC()
	results := make([]model.PortHealth, len(probes))
	localAddresses := localAddressSet()
	jobs := make(chan int)
	workers := len(probes)
	if workers > 48 {
		workers = 48
	}
	var group sync.WaitGroup
	for range workers {
		group.Add(1)
		go func() {
			defer group.Done()
			for index := range jobs {
				probe := probes[index]
				result := model.PortHealth{Key: probe.key, Kind: probe.kind, Port: probe.port, CheckedAt: checkedAt.Format(time.RFC3339Nano)}
				if !probe.supported {
					result.Status = "unsupported"
					results[index] = result
					continue
				}
				address, err := localProbeAddress(probe.host, probe.port, localAddresses)
				if err != nil {
					result.Status, result.Error = "unhealthy", boundedProbeError(err)
					results[index] = result
					continue
				}
				started := time.Now()
				connection, err := (&net.Dialer{Timeout: time.Second, KeepAlive: -1}).DialContext(ctx, "tcp", address)
				if err != nil {
					result.Status, result.Error = "unhealthy", boundedProbeError(err)
				} else {
					result.Status = "healthy"
					result.LatencyMS = max(1, time.Since(started).Milliseconds())
					_ = connection.Close()
				}
				results[index] = result
			}
		}()
	}
	for index := range probes {
		select {
		case jobs <- index:
		case <-ctx.Done():
			close(jobs)
			group.Wait()
			fillCanceledProbes(results, probes, checkedAt, ctx.Err())
			return results
		}
	}
	close(jobs)
	group.Wait()
	fillCanceledProbes(results, probes, checkedAt, ctx.Err())
	return results
}

func portProbes(integrations model.Integrations) []portProbe {
	probes := make([]portProbe, 0)
	if integrations.MMW != nil {
		for _, node := range integrations.MMW.Nodes {
			key := node.Tag
			if key == "" {
				key = "node"
			}
			network := strings.ToLower(node.Network)
			probes = append(probes, portProbe{key: "mmw:" + key + ":" + strconv.Itoa(int(node.Port)), kind: "mmw", host: node.Listen, port: node.Port, supported: network != "kcp" && network != "mkcp" && network != "quic"})
		}
	}
	if integrations.ForwardX != nil {
		for _, rule := range integrations.ForwardX.Rules {
			host, _, err := net.SplitHostPort(strings.TrimSpace(rule.Listen))
			if err != nil {
				host = "invalid"
			}
			protocol := strings.ToLower(rule.Protocol)
			probes = append(probes, portProbe{key: "forwardx:" + rule.ID + ":" + strconv.Itoa(int(rule.ListenPort)), kind: "forwardx", host: host, port: rule.ListenPort, supported: protocol == "tcp" || protocol == "tcp+udp"})
		}
	}
	return probes
}

func localAddressSet() map[netip.Addr]bool {
	addresses := make(map[netip.Addr]bool)
	interfaces, _ := net.InterfaceAddrs()
	for _, value := range interfaces {
		prefix, err := netip.ParsePrefix(value.String())
		if err == nil {
			addresses[prefix.Addr().Unmap()] = true
		}
	}
	return addresses
}

func localProbeAddress(host string, port uint16, localAddresses map[netip.Addr]bool) (string, error) {
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if host == "" || host == "*" || host == "0.0.0.0" {
		return net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))), nil
	}
	if host == "::" {
		return net.JoinHostPort("::1", strconv.Itoa(int(port))), nil
	}
	if strings.EqualFold(host, "localhost") {
		return net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))), nil
	}
	address, err := netip.ParseAddr(host)
	if err != nil {
		return "", errors.New("监听地址不是本机IP")
	}
	address = address.Unmap()
	if !address.IsLoopback() && !localAddresses[address] {
		return "", errors.New("监听地址不属于本机网卡")
	}
	return net.JoinHostPort(address.String(), strconv.Itoa(int(port))), nil
}

func fillCanceledProbes(results []model.PortHealth, probes []portProbe, checkedAt time.Time, cause error) {
	for index := range results {
		if results[index].Status != "" {
			continue
		}
		results[index] = model.PortHealth{
			Key: probes[index].key, Kind: probes[index].kind, Port: probes[index].port,
			Status: "unhealthy", Error: boundedProbeError(cause), CheckedAt: checkedAt.Format(time.RFC3339Nano),
		}
	}
}

func boundedProbeError(err error) string {
	if err == nil {
		return "探测未完成"
	}
	message := err.Error()
	if len(message) > 256 {
		message = message[:256]
	}
	return message
}
