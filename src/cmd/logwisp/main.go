// FILE: src/cmd/logwisp/main.go
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"logwisp/src/internal/config"
	"logwisp/src/internal/service"
	"logwisp/src/internal/version"
)

func main() {
	// Parse CLI flags
	var (
		configFile = flag.String("config", "", "Config file path")
		useRouter  = flag.Bool("router", false, "Use HTTP router for path-based routing")
		// routerPort = flag.Int("router-port", 0, "Override router port (default: first HTTP port)")
		showVersion = flag.Bool("version", false, "Show version information")
	)
	flag.Parse()

	if *showVersion {
		fmt.Println(version.String())
		os.Exit(0)
	}

	if *configFile != "" {
		os.Setenv("LOGWISP_CONFIG_FILE", *configFile)
	}

	// Load configuration
	cfg, err := config.LoadWithCLI(os.Args[1:])
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}

	// Create context for shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Create log transport service
	svc := service.New(ctx)

	// Create HTTP router if requested
	var router *service.HTTPRouter
	if *useRouter {
		router = service.NewHTTPRouter(svc)
		fmt.Println("HTTP router mode enabled")
	}

	// Initialize streams
	successCount := 0
	for _, streamCfg := range cfg.Streams {
		fmt.Printf("Initializing transport '%s'...\n", streamCfg.Name)

		// Set router mode BEFORE creating transport
		if *useRouter && streamCfg.HTTPServer != nil && streamCfg.HTTPServer.Enabled {
			// Temporarily disable standalone server startup
			originalEnabled := streamCfg.HTTPServer.Enabled
			streamCfg.HTTPServer.Enabled = false

			if err := svc.CreateStream(streamCfg); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to create transport '%s': %v\n", streamCfg.Name, err)
				continue
			}

			// Get the created transport and configure for router mode
			stream, _ := svc.GetStream(streamCfg.Name)
			if stream.HTTPServer != nil {
				stream.HTTPServer.SetRouterMode()
				// Restore enabled state
				stream.Config.HTTPServer.Enabled = originalEnabled

				if err := router.RegisterStream(stream); err != nil {
					fmt.Fprintf(os.Stderr, "Failed to register transport '%s' with router: %v\n",
						streamCfg.Name, err)
				} else {
					fmt.Printf("Stream '%s' registered with router\n", streamCfg.Name)
				}
			}
		} else {
			// Standard standalone mode
			if err := svc.CreateStream(streamCfg); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to create transport '%s': %v\n", streamCfg.Name, err)
				continue
			}
		}

		successCount++

		// Display endpoints
		displayStreamEndpoints(streamCfg, *useRouter)
	}

	if successCount == 0 {
		fmt.Fprintln(os.Stderr, "No streams successfully started")
		os.Exit(1)
	}

	fmt.Printf("LogWisp %s\n", version.Short())
	fmt.Printf("\n%d transport(s) running. Press Ctrl+C to stop.\n", successCount)

	// Start periodic status display
	go statusReporter(svc)

	// Wait for shutdown
	<-sigChan
	fmt.Println("\nShutting down...")

	// Shutdown router first if using it
	if router != nil {
		fmt.Println("Shutting down HTTP router...")
		router.Shutdown()
	}

	// Shutdown service (handles all streams)
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	done := make(chan struct{})
	go func() {
		svc.Shutdown()
		close(done)
	}()

	select {
	case <-done:
		fmt.Println("Shutdown complete")
	case <-shutdownCtx.Done():
		fmt.Println("Shutdown timeout - forcing exit")
		os.Exit(1)
	}
}

func displayStreamEndpoints(cfg config.StreamConfig, routerMode bool) {
	if cfg.TCPServer != nil && cfg.TCPServer.Enabled {
		fmt.Printf("  TCP: port %d\n", cfg.TCPServer.Port)
	}

	if cfg.HTTPServer != nil && cfg.HTTPServer.Enabled {
		if routerMode {
			fmt.Printf("  HTTP: /%s%s (transport), /%s%s (status)\n",
				cfg.Name, cfg.HTTPServer.StreamPath,
				cfg.Name, cfg.HTTPServer.StatusPath)
		} else {
			fmt.Printf("  HTTP: http://localhost:%d%s (transport), http://localhost:%d%s (status)\n",
				cfg.HTTPServer.Port, cfg.HTTPServer.StreamPath,
				cfg.HTTPServer.Port, cfg.HTTPServer.StatusPath)
		}

		if cfg.Auth != nil && cfg.Auth.Type != "none" {
			fmt.Printf("  Auth: %s\n", cfg.Auth.Type)
		}
	}
}

func statusReporter(service *service.Service) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		stats := service.GetGlobalStats()
		totalStreams := stats["total_streams"].(int)
		if totalStreams == 0 {
			return
		}

		fmt.Printf("\n[%s] Active streams: %d\n",
			time.Now().Format("15:04:05"), totalStreams)

		for name, streamStats := range stats["streams"].(map[string]interface{}) {
			s := streamStats.(map[string]interface{})
			fmt.Printf("  %s: ", name)

			if monitor, ok := s["monitor"].(map[string]interface{}); ok {
				fmt.Printf("watchers=%d entries=%d ",
					monitor["active_watchers"],
					monitor["total_entries"])
			}

			if tcp, ok := s["tcp"].(map[string]interface{}); ok && tcp["enabled"].(bool) {
				fmt.Printf("tcp_conns=%d ", tcp["connections"])
			}

			if http, ok := s["http"].(map[string]interface{}); ok && http["enabled"].(bool) {
				fmt.Printf("http_conns=%d ", http["connections"])
			}

			fmt.Println()
		}
	}
}