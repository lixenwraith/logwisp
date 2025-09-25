// FILE: src/cmd/logwisp/signals.go
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/lixenwraith/log"
)

// Manages OS signals
type SignalHandler struct {
	reloadManager *ReloadManager
	logger        *log.Logger
	sigChan       chan os.Signal
}

// Creates a signal handler
func NewSignalHandler(rm *ReloadManager, logger *log.Logger) *SignalHandler {
	sh := &SignalHandler{
		reloadManager: rm,
		logger:        logger,
		sigChan:       make(chan os.Signal, 1),
	}

	// Register for signals
	signal.Notify(sh.sigChan,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGHUP,  // Traditional reload signal
		syscall.SIGUSR1, // Alternative reload signal
	)

	return sh
}

// Processes signals
func (sh *SignalHandler) Handle(ctx context.Context) os.Signal {
	for {
		select {
		case sig := <-sh.sigChan:
			switch sig {
			case syscall.SIGHUP, syscall.SIGUSR1:
				sh.logger.Info("msg", "Reload signal received",
					"signal", sig)
				// Trigger manual reload
				go sh.reloadManager.triggerReload(ctx)
				// Continue handling signals
			default:
				// Return termination signals
				return sig
			}
		case <-ctx.Done():
			return nil
		}
	}
}

// Cleans up signal handling
func (sh *SignalHandler) Stop() {
	signal.Stop(sh.sigChan)
	close(sh.sigChan)
}