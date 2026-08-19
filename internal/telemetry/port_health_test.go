package telemetry

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/T-Matrix/mmwx-guard/internal/model"
)

func TestProbePortHealthChecksOnlyLocalTCPListeners(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := uint16(listener.Addr().(*net.TCPAddr).Port)

	closedListener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedPort := uint16(closedListener.Addr().(*net.TCPAddr).Port)
	closedListener.Close()

	integrations := model.Integrations{
		MMW: &model.MMWIntegration{Nodes: []model.MMWNodeListener{
			{Tag: "healthy", Listen: "127.0.0.1", Port: port, Network: "tcp"},
			{Tag: "udp", Listen: "127.0.0.1", Port: port, Network: "quic"},
		}},
		ForwardX: &model.ForwardXIntegration{Rules: []model.ForwardRule{
			{ID: "closed", Protocol: "tcp", Listen: net.JoinHostPort("127.0.0.1", strconv.Itoa(int(closedPort))), ListenPort: closedPort, Remote: "198.51.100.8:443"},
			{ID: "external", Protocol: "tcp", Listen: "198.51.100.9:1234", ListenPort: 1234, Remote: "198.51.100.10:443"},
		}},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	results := probePortHealth(ctx, integrations)
	if len(results) != 4 {
		t.Fatalf("health results = %#v", results)
	}
	if results[0].Status != "healthy" || results[0].LatencyMS < 1 {
		t.Fatalf("healthy listener = %#v", results[0])
	}
	if results[1].Status != "unsupported" {
		t.Fatalf("UDP listener = %#v", results[1])
	}
	if results[2].Status != "unhealthy" || results[2].Error == "" {
		t.Fatalf("closed listener = %#v", results[2])
	}
	if results[3].Status != "unhealthy" || results[3].Error != "监听地址不属于本机网卡" {
		t.Fatalf("external listen address = %#v", results[3])
	}
}
