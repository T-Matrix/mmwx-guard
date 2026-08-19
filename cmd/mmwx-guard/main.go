package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/T-Matrix/mmwx-guard/internal/controller"
	"github.com/T-Matrix/mmwx-guard/internal/store"
	"github.com/T-Matrix/mmwx-guard/internal/updater"
	"github.com/T-Matrix/mmwx-guard/internal/webui"
)

var version = "dev"

func main() {
	listen := flag.String("listen", ":9080", "HTTP listen address")
	databasePath := flag.String("database", "/var/lib/mmwx-guard/controller.db", "SQLite database path")
	publicURL := flag.String("public-url", "", "public controller URL used in Agent install commands")
	agentDir := flag.String("agent-dir", "/usr/lib/mmwx-guard", "directory containing Agent binaries")
	updateDir := flag.String("update-dir", "/var/lib/mmwx-guard/update", "controller update request and status directory")
	releaseRepo := flag.String("release-repo", updater.DefaultRepository, "GitHub repository used for updates")
	showVersion := flag.Bool("version", false, "print version and exit")
	applyUpdate := flag.Bool("apply-update", false, "apply a queued controller update and exit")
	installPath := flag.String("install-path", "/usr/local/bin/mmwx-guard", "controller binary path used by the update helper")
	serviceName := flag.String("service-name", "mmwx-guard.service", "controller systemd service used by the update helper")
	healthURL := flag.String("health-url", "http://127.0.0.1:9080/healthz", "controller health URL used by the update helper")
	flag.Parse()
	if *showVersion {
		_, _ = os.Stdout.WriteString(version + "\n")
		return
	}
	if *applyUpdate {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		err := updater.ApplyControllerUpdate(ctx, updater.ApplyOptions{
			Repository: *releaseRepo, UpdateDir: *updateDir, InstallPath: *installPath,
			AgentDir: *agentDir, ServiceName: *serviceName, HealthURL: *healthURL,
		})
		if err != nil {
			log.Fatalf("apply controller update: %v", err)
		}
		return
	}

	if err := os.MkdirAll(filepath.Dir(*databasePath), 0700); err != nil {
		log.Fatalf("create data directory: %v", err)
	}
	database, err := store.Open(*databasePath)
	if err != nil {
		log.Fatalf("open database: %v", err)
	}
	defer database.Close()
	if err := database.EnsureDefaultPolicy(context.Background()); err != nil {
		log.Fatalf("create default policy: %v", err)
	}

	updateManager := updater.NewManager(*releaseRepo, version, *updateDir)
	server, err := controller.NewServer(database, webui.Handler(), version, *publicURL, *agentDir, updateManager)
	if err != nil {
		log.Fatalf("configure controller: %v", err)
	}
	httpServer := &http.Server{
		Addr:              *listen,
		Handler:           server.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
	log.Printf("妙妙屋X安全防护 %s listening on %s", version, *listen)
	if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
