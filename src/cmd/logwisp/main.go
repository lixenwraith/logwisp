// FILE: src/cmd/logwisp/main.go
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"logwisp/src/internal/config"
	"logwisp/src/internal/monitor"
	"logwisp/src/internal/stream"
)

func main() {
	// Parse CLI flags
	var (
		configFile = flag.String("config", "", "Config file path")
		// Legacy compatibility flags
		port       = flag.Int("port", 0, "HTTP port (legacy, maps to --http-port)")
		bufferSize = flag.Int("buffer-size", 0, "Buffer size (legacy, maps to --http-buffer-size)")
		// New explicit flags
		httpPort      = flag.Int("http-port", 0, "HTTP server port")
		httpBuffer    = flag.Int("http-buffer-size", 0, "HTTP server buffer size")
		tcpPort       = flag.Int("tcp-port", 0, "TCP server port")
		tcpBuffer     = flag.Int("tcp-buffer-size", 0, "TCP server buffer size")
		enableTCP     = flag.Bool("enable-tcp", false, "Enable TCP server")
		enableHTTP    = flag.Bool("enable-http", false, "Enable HTTP server")
		checkInterval = flag.Int("check-interval", 0, "File check interval in ms")
	)
	flag.Parse()

	if *configFile != "" {
		os.Setenv("LOGWISP_CONFIG_FILE", *configFile)
	}

	// Build CLI args for config
	var cliArgs []string

	// Legacy mapping
	if *port > 0 {
		cliArgs = append(cliArgs, fmt.Sprintf("--httpserver.port=%d", *port))
	}
	if *bufferSize > 0 {
		cliArgs = append(cliArgs, fmt.Sprintf("--httpserver.buffer_size=%d", *bufferSize))
	}

	// New flags
	if *httpPort > 0 {
		cliArgs = append(cliArgs, fmt.Sprintf("--httpserver.port=%d", *httpPort))
	}
	if *httpBuffer > 0 {
		cliArgs = append(cliArgs, fmt.Sprintf("--httpserver.buffer_size=%d", *httpBuffer))
	}
	if *tcpPort > 0 {
		cliArgs = append(cliArgs, fmt.Sprintf("--tcpserver.port=%d", *tcpPort))
	}
	if *tcpBuffer > 0 {
		cliArgs = append(cliArgs, fmt.Sprintf("--tcpserver.buffer_size=%d", *tcpBuffer))
	}
	if flag.Lookup("enable-tcp").DefValue != flag.Lookup("enable-tcp").Value.String() {
		cliArgs = append(cliArgs, fmt.Sprintf("--tcpserver.enabled=%v", *enableTCP))
	}
	if flag.Lookup("enable-http").DefValue != flag.Lookup("enable-http").Value.String() {
		cliArgs = append(cliArgs, fmt.Sprintf("--httpserver.enabled=%v", *enableHTTP))
	}
	if *checkInterval > 0 {
		cliArgs = append(cliArgs, fmt.Sprintf("--monitor.check_interval_ms=%d", *checkInterval))
	}

	// Parse monitor targets from remaining args
	for _, arg := range flag.Args() {
		cliArgs = append(cliArgs, fmt.Sprintf("--monitor.targets.add=%s", arg))
	}

	// Load configuration
	cfg, err := config.LoadWithCLI(cliArgs)
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

	var wg sync.WaitGroup

	// Create monitor
	mon := monitor.New()
	mon.SetCheckInterval(time.Duration(cfg.Monitor.CheckIntervalMs) * time.Millisecond)

	// Add targets
	for _, target := range cfg.Monitor.Targets {
		if err := mon.AddTarget(target.Path, target.Pattern, target.IsFile); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to add target %s: %v\n", target.Path, err)
		}
	}

	// Start monitor
	if err := mon.Start(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to start monitor: %v\n", err)
		os.Exit(1)
	}

	var tcpServer *stream.TCPStreamer
	var httpServer *stream.HTTPStreamer

	// Start TCP server if enabled
	if cfg.TCPServer.Enabled {
		tcpChan := mon.Subscribe()
		tcpServer = stream.NewTCPStreamer(tcpChan, cfg.TCPServer)

		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := tcpServer.Start(); err != nil {
				fmt.Fprintf(os.Stderr, "TCP server error: %v\n", err)
			}
		}()

		fmt.Printf("TCP streaming on port %d\n", cfg.TCPServer.Port)
	}

	// Start HTTP server if enabled
	if cfg.HTTPServer.Enabled {
		httpChan := mon.Subscribe()
		httpServer = stream.NewHTTPStreamer(httpChan, cfg.HTTPServer)

		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := httpServer.Start(); err != nil {
				fmt.Fprintf(os.Stderr, "HTTP server error: %v\n", err)
			}
		}()

		fmt.Printf("HTTP/SSE streaming on http://localhost:%d/stream\n", cfg.HTTPServer.Port)
		fmt.Printf("Status available at http://localhost:%d/status\n", cfg.HTTPServer.Port)
	}

	if !cfg.TCPServer.Enabled && !cfg.HTTPServer.Enabled {
		fmt.Fprintln(os.Stderr, "No servers enabled. Enable at least one server in config.")
		os.Exit(1)
	}

	// Wait for shutdown
	<-sigChan
	fmt.Println("\nShutting down...")

	// Stop servers first
	if tcpServer != nil {
		tcpServer.Stop()
	}
	if httpServer != nil {
		httpServer.Stop()
	}

	// Cancel context and stop monitor
	cancel()
	mon.Stop()

	// Wait for completion
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		fmt.Println("Shutdown complete")
	case <-time.After(2 * time.Second):
		fmt.Println("Shutdown timeout")
	}
}