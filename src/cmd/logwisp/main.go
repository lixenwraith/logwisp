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
		// Flags
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

	// Flags
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

		// Start TCP server in separate goroutine without blocking wg.Wait()
		tcpStarted := make(chan error, 1)
		go func() {
			tcpStarted <- tcpServer.Start()
		}()

		// Check if TCP server started successfully
		select {
		case err := <-tcpStarted:
			if err != nil {
				fmt.Fprintf(os.Stderr, "TCP server failed to start: %v\n", err)
				os.Exit(1)
			}
		case <-time.After(1 * time.Second):
			// Server is running
		}

		fmt.Printf("TCP streaming on port %d\n", cfg.TCPServer.Port)
	}

	// Start HTTP server if enabled
	if cfg.HTTPServer.Enabled {
		httpChan := mon.Subscribe()
		httpServer = stream.NewHTTPStreamer(httpChan, cfg.HTTPServer)

		// Start HTTP server in separate goroutine without blocking wg.Wait()
		httpStarted := make(chan error, 1)
		go func() {
			httpStarted <- httpServer.Start()
		}()

		// Check if HTTP server started successfully
		select {
		case err := <-httpStarted:
			if err != nil {
				fmt.Fprintf(os.Stderr, "HTTP server failed to start: %v\n", err)
				os.Exit(1)
			}
		case <-time.After(1 * time.Second):
			// Server is running
		}

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

	// Create shutdown group for concurrent server stops
	var shutdownWg sync.WaitGroup

	// Stop servers first (concurrently)
	if tcpServer != nil {
		shutdownWg.Add(1)
		go func() {
			defer shutdownWg.Done()
			tcpServer.Stop()
		}()
	}
	if httpServer != nil {
		shutdownWg.Add(1)
		go func() {
			defer shutdownWg.Done()
			httpServer.Stop()
		}()
	}

	// Cancel context to stop monitor
	cancel()

	// Wait for servers to stop with timeout
	serversDone := make(chan struct{})
	go func() {
		shutdownWg.Wait()
		close(serversDone)
	}()

	// Stop monitor after context cancellation
	monitorDone := make(chan struct{})
	go func() {
		mon.Stop()
		close(monitorDone)
	}()

	// Wait for all components with proper timeout
	shutdownTimeout := 5 * time.Second
	shutdownTimer := time.NewTimer(shutdownTimeout)
	defer shutdownTimer.Stop()

	serversShutdown := false
	monitorShutdown := false

	for !serversShutdown || !monitorShutdown {
		select {
		case <-serversDone:
			serversShutdown = true
		case <-monitorDone:
			monitorShutdown = true
		case <-shutdownTimer.C:
			if !serversShutdown {
				fmt.Println("Warning: Server shutdown timeout")
			}
			if !monitorShutdown {
				fmt.Println("Warning: Monitor shutdown timeout")
			}
			fmt.Println("Forcing exit")
			os.Exit(1)
		}
	}

	fmt.Println("Shutdown complete")
}