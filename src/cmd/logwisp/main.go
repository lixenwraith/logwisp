// File: logwisp/src/cmd/logwisp/main.go
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"logwisp/src/internal/config"
	"logwisp/src/internal/middleware"
	"logwisp/src/internal/monitor"
	"logwisp/src/internal/stream"
)

func main() {
	// CHANGED: Parse flags manually without init()
	var colorMode bool
	flag.BoolVar(&colorMode, "c", false, "Enable color pass-through for escape codes in logs")

	// Additional CLI flags that override config
	var (
		port          = flag.Int("port", 0, "HTTP port (overrides config)")
		bufferSize    = flag.Int("buffer-size", 0, "Stream buffer size (overrides config)")
		checkInterval = flag.Int("check-interval", 0, "File check interval in ms (overrides config)")
		rateLimit     = flag.Bool("rate-limit", false, "Enable rate limiting (overrides config)")
		rateRequests  = flag.Int("rate-requests", 0, "Rate limit requests/sec (overrides config)")
		rateBurst     = flag.Int("rate-burst", 0, "Rate limit burst size (overrides config)")
		configFile    = flag.String("config", "", "Config file path (overrides LOGWISP_CONFIG_FILE)")
	)

	flag.Parse()

	// Set config file env var if specified via CLI
	if *configFile != "" {
		os.Setenv("LOGWISP_CONFIG_FILE", *configFile)
	}

	// Build CLI override args for config package
	var cliArgs []string
	if *port > 0 {
		cliArgs = append(cliArgs, fmt.Sprintf("--port=%d", *port))
	}
	if *bufferSize > 0 {
		cliArgs = append(cliArgs, fmt.Sprintf("--stream.buffer_size=%d", *bufferSize))
	}
	if *checkInterval > 0 {
		cliArgs = append(cliArgs, fmt.Sprintf("--monitor.check_interval_ms=%d", *checkInterval))
	}
	if flag.Lookup("rate-limit").DefValue != flag.Lookup("rate-limit").Value.String() {
		// Rate limit flag was explicitly set
		cliArgs = append(cliArgs, fmt.Sprintf("--stream.rate_limit.enabled=%v", *rateLimit))
	}
	if *rateRequests > 0 {
		cliArgs = append(cliArgs, fmt.Sprintf("--stream.rate_limit.requests_per_second=%d", *rateRequests))
	}
	if *rateBurst > 0 {
		cliArgs = append(cliArgs, fmt.Sprintf("--stream.rate_limit.burst_size=%d", *rateBurst))
	}

	// Parse remaining args as monitor targets
	for _, arg := range flag.Args() {
		if strings.Contains(arg, ":") {
			// Format: path:pattern:isfile
			cliArgs = append(cliArgs, fmt.Sprintf("--monitor.targets.add=%s", arg))
		} else if stat, err := os.Stat(arg); err == nil {
			// Auto-detect file vs directory
			if stat.IsDir() {
				cliArgs = append(cliArgs, fmt.Sprintf("--monitor.targets.add=%s:*.log:false", arg))
			} else {
				cliArgs = append(cliArgs, fmt.Sprintf("--monitor.targets.add=%s::true", arg))
			}
		}
	}

	// Load configuration with CLI overrides
	cfg, err := config.LoadWithCLI(cliArgs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())

	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// WaitGroup for tracking all goroutines
	var wg sync.WaitGroup

	// Create components
	// colorMode is now separate from config
	streamer := stream.NewWithOptions(cfg.Stream.BufferSize, colorMode)
	mon := monitor.New(streamer.Publish)

	// Set monitor check interval from config
	mon.SetCheckInterval(time.Duration(cfg.Monitor.CheckIntervalMs) * time.Millisecond)

	// Add monitor targets from config
	for _, target := range cfg.Monitor.Targets {
		if err := mon.AddTarget(target.Path, target.Pattern, target.IsFile); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to add target %s: %v\n", target.Path, err)
		}
	}

	// Start monitoring
	if err := mon.Start(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to start monitor: %v\n", err)
		os.Exit(1)
	}

	// Setup HTTP server
	mux := http.NewServeMux()

	// Create handler with optional rate limiting
	var handler http.Handler = streamer
	var rateLimiter *middleware.RateLimiter

	if cfg.Stream.RateLimit.Enabled {
		rateLimiter = middleware.NewRateLimiter(
			cfg.Stream.RateLimit.RequestsPerSecond,
			cfg.Stream.RateLimit.BurstSize,
			cfg.Stream.RateLimit.CleanupIntervalS,
		)
		handler = rateLimiter.Middleware(handler)
		fmt.Printf("Rate limiting enabled: %d req/s, burst %d\n",
			cfg.Stream.RateLimit.RequestsPerSecond,
			cfg.Stream.RateLimit.BurstSize)
	}

	mux.Handle("/stream", handler)

	// Enhanced status endpoint
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		status := map[string]interface{}{
			"service":    "LogWisp",
			"version":    "2.0.0", // CHANGED: Version bump for config integration
			"port":       cfg.Port,
			"color_mode": colorMode,
			"config": map[string]interface{}{
				"monitor": map[string]interface{}{
					"check_interval_ms": cfg.Monitor.CheckIntervalMs,
					"targets_count":     len(cfg.Monitor.Targets),
				},
				"stream": map[string]interface{}{
					"buffer_size": cfg.Stream.BufferSize,
					"rate_limit": map[string]interface{}{
						"enabled":             cfg.Stream.RateLimit.Enabled,
						"requests_per_second": cfg.Stream.RateLimit.RequestsPerSecond,
						"burst_size":          cfg.Stream.RateLimit.BurstSize,
					},
				},
			},
		}

		// Add runtime stats
		if rateLimiter != nil {
			status["rate_limiter"] = rateLimiter.Stats()
		}
		status["streamer"] = streamer.Stats()

		json.NewEncoder(w).Encode(status)
	})

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", cfg.Port),
		Handler: mux,
		// Add timeouts for better shutdown behavior
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Start server in goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		fmt.Printf("LogWisp streaming on http://localhost:%d/stream\n", cfg.Port)
		fmt.Printf("Status available at http://localhost:%d/status\n", cfg.Port)
		if colorMode {
			fmt.Println("Color pass-through enabled")
		}
		// CHANGED: Log config source information
		fmt.Printf("Config loaded from: %s\n", config.GetConfigPath())

		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
		}
	}()

	// Wait for shutdown signal
	<-sigChan
	fmt.Println("\nShutting down...")

	// Cancel context to stop all components
	cancel()

	// Create shutdown context with timeout
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()

	// Shutdown server first
	if err := server.Shutdown(shutdownCtx); err != nil {
		fmt.Fprintf(os.Stderr, "Server shutdown error: %v\n", err)
		// Force close if graceful shutdown fails
		server.Close()
	}

	// Stop all components
	mon.Stop()
	streamer.Stop()

	if rateLimiter != nil {
		rateLimiter.Stop()
	}

	// Wait for all goroutines with timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		fmt.Println("Shutdown complete")
	case <-time.After(2 * time.Second):
		fmt.Println("Shutdown timeout, forcing exit")
	}
}