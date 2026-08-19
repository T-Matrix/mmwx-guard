package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/T-Matrix/mmwx-guard/internal/agent"
	"github.com/T-Matrix/mmwx-guard/internal/updater"
)

var version = "dev"

func main() {
	var (
		controller  = flag.String("controller", "", "controller URL used for first enrollment")
		token       = flag.String("token", "", "one-time enrollment token")
		name        = flag.String("name", "", "agent display name")
		configPath  = flag.String("config", "/etc/mmwx-guard/agent.json", "agent config path")
		stateDir    = flag.String("state-dir", "/var/lib/mmwx-guard", "agent state directory")
		dryRun      = flag.Bool("dry-run", false, "validate and persist policies without calling nft")
		enrollOnly  = flag.Bool("enroll-only", false, "enroll, save credentials, and exit")
		showVersion = flag.Bool("version", false, "print version and exit")
		applyUpdate = flag.Bool("apply-agent-update", false, "apply a queued Agent update and exit")
		installPath = flag.String("install-path", "/usr/local/bin/mmwx-guard-agent", "Agent binary path used by the update helper")
		serviceName = flag.String("service-name", "mmwx-guard-agent.service", "Agent systemd service used by the update helper")
	)
	flag.Parse()
	if *showVersion {
		_, _ = os.Stdout.WriteString(version + "\n")
		return
	}
	if *applyUpdate {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		defer cancel()
		err := updater.ApplyAgentUpdate(ctx, updater.AgentApplyOptions{
			UpdateDir: filepath.Join(*stateDir, "agent-update"), StateDir: *stateDir,
			InstallPath: *installPath, ServiceName: *serviceName,
		})
		if err != nil {
			log.Fatalf("apply Agent update: %v", err)
		}
		return
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	enrollCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	options := agent.Options{ConfigPath: *configPath, StateDir: *stateDir, Version: version, DryRun: *dryRun}
	if *enrollOnly {
		err := agent.EnrollOnly(enrollCtx, options, *controller, *token, *name)
		cancel()
		if err != nil {
			log.Fatalf("enroll agent: %v", err)
		}
		log.Printf("妙妙屋X安全防护 Agent 注册完成")
		return
	}
	client, err := agent.LoadOrEnroll(enrollCtx, options, *controller, *token, *name)
	cancel()
	if err != nil {
		log.Fatalf("initialize agent: %v", err)
	}
	log.Printf("妙妙屋X安全防护 Agent %s started (pid=%d)", version, os.Getpid())
	if err := client.Run(ctx); err != nil && ctx.Err() == nil {
		log.Fatalf("agent stopped: %v", err)
	}
}
