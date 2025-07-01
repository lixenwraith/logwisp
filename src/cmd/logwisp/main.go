// File: logwisp/src/cmd/logwisp/main.go
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"logwisp/src/internal/config"
	"logwisp/src/internal/monitor"
	"logwisp/src/internal/stream"
)

func main() {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		os.Exit(1)
	}

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Create components
	streamer := stream.New(cfg.Stream.BufferSize)
	mon := monitor.New(streamer.Publish)

	// Add monitor targets from config
	for _, target := range cfg.Monitor.Targets {
		if err := mon.AddTarget(target.Path, target.Pattern); err != nil {
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
	mux.Handle("/stream", streamer)

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", cfg.Port),
		Handler: mux,
	}

	// Start server
	go func() {
		fmt.Printf("LogWisp streaming on http://localhost:%d/stream\n", cfg.Port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Fprintf(os.Stderr, "Server error: %v\n", err)
		}
	}()

	// Wait for shutdown signal
	<-sigChan
	fmt.Println("\nShutting down...")

	// Graceful shutdown
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		fmt.Fprintf(os.Stderr, "Server shutdown error: %v\n", err)
	}

	cancel() // Stop monitor
	mon.Stop()
	streamer.Stop()
}