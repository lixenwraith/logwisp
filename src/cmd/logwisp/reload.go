// FILE: src/cmd/logwisp/reload.go
package main

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"logwisp/src/internal/config"
	"logwisp/src/internal/service"

	lconfig "github.com/lixenwraith/config"
	"github.com/lixenwraith/log"
)

// ReloadManager handles configuration hot reload
type ReloadManager struct {
	configPath  string
	service     *service.Service
	cfg         *config.Config
	lcfg        *lconfig.Config
	logger      *log.Logger
	mu          sync.RWMutex
	reloadingMu sync.Mutex
	isReloading bool
	shutdownCh  chan struct{}
	wg          sync.WaitGroup

	// Status reporter management
	statusReporterCancel context.CancelFunc
	statusReporterMu     sync.Mutex
}

// NewReloadManager creates a new reload manager
func NewReloadManager(configPath string, initialCfg *config.Config, logger *log.Logger) *ReloadManager {
	return &ReloadManager{
		configPath: configPath,
		cfg:        initialCfg,
		logger:     logger,
		shutdownCh: make(chan struct{}),
	}
}

// Start begins watching for configuration changes
func (rm *ReloadManager) Start(ctx context.Context) error {
	// Bootstrap initial service
	svc, err := bootstrapService(ctx, rm.cfg)
	if err != nil {
		return fmt.Errorf("failed to bootstrap initial service: %w", err)
	}

	rm.mu.Lock()
	rm.service = svc
	rm.mu.Unlock()

	// Start status reporter for initial service
	if !rm.cfg.DisableStatusReporter {
		rm.startStatusReporter(ctx, svc)
	}

	// Create lconfig instance for file watching, logwisp config is always TOML
	lcfg, err := lconfig.NewBuilder().
		WithFile(rm.configPath).
		WithTarget(rm.cfg).
		WithFileFormat("toml").
		WithSecurityOptions(lconfig.SecurityOptions{
			PreventPathTraversal: true,
			MaxFileSize:          10 * 1024 * 1024,
		}).
		Build()
	if err != nil {
		return fmt.Errorf("failed to create config watcher: %w", err)
	}

	rm.lcfg = lcfg

	// Enable auto-update with custom options
	watchOpts := lconfig.WatchOptions{
		PollInterval:      time.Second,
		Debounce:          500 * time.Millisecond,
		ReloadTimeout:     30 * time.Second,
		VerifyPermissions: true, // TODO: Prevent malicious config replacement, to be implemented
	}
	lcfg.AutoUpdateWithOptions(watchOpts)

	// Start watching for changes
	rm.wg.Add(1)
	go rm.watchLoop(ctx)

	rm.logger.Info("msg", "Configuration hot reload enabled",
		"config_file", rm.configPath)

	return nil
}

// watchLoop monitors configuration changes
func (rm *ReloadManager) watchLoop(ctx context.Context) {
	defer rm.wg.Done()

	changeCh := rm.lcfg.Watch()

	for {
		select {
		case <-ctx.Done():
			return
		case <-rm.shutdownCh:
			return
		case changedPath := <-changeCh:
			// Handle special notifications
			switch changedPath {
			case "file_deleted":
				rm.logger.Error("msg", "Configuration file deleted",
					"action", "keeping current configuration")
				continue
			case "permissions_changed":
				// SECURITY: Config file permissions changed suspiciously
				rm.logger.Error("msg", "Configuration file permissions changed",
					"action", "reload blocked for security")
				continue
			case "reload_timeout":
				rm.logger.Error("msg", "Configuration reload timed out",
					"action", "keeping current configuration")
				continue
			default:
				if strings.HasPrefix(changedPath, "reload_error:") {
					rm.logger.Error("msg", "Configuration reload error",
						"error", strings.TrimPrefix(changedPath, "reload_error:"),
						"action", "keeping current configuration")
					continue
				}
			}

			// Trigger reload for any pipeline-related change
			if rm.shouldReload(changedPath) {
				rm.triggerReload(ctx)
			}
		}
	}
}

// shouldReload determines if a config change requires service reload
func (rm *ReloadManager) shouldReload(path string) bool {
	// Pipeline changes always require reload
	if strings.HasPrefix(path, "pipelines.") || path == "pipelines" {
		return true
	}

	// Logging changes don't require service reload
	if strings.HasPrefix(path, "logging.") {
		return false
	}

	// Status reporter changes
	if path == "disable_status_reporter" {
		return true
	}

	return false
}

// triggerReload performs the actual reload
func (rm *ReloadManager) triggerReload(ctx context.Context) {
	// Prevent concurrent reloads
	rm.reloadingMu.Lock()
	if rm.isReloading {
		rm.reloadingMu.Unlock()
		rm.logger.Debug("msg", "Reload already in progress, skipping")
		return
	}
	rm.isReloading = true
	rm.reloadingMu.Unlock()

	defer func() {
		rm.reloadingMu.Lock()
		rm.isReloading = false
		rm.reloadingMu.Unlock()
	}()

	rm.logger.Info("msg", "Starting configuration hot reload")

	// Create reload context with timeout
	reloadCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	if err := rm.performReload(reloadCtx); err != nil {
		rm.logger.Error("msg", "Hot reload failed",
			"error", err,
			"action", "keeping current configuration and services")
		return
	}

	rm.logger.Info("msg", "Configuration hot reload completed successfully")
}

// performReload executes the reload process
func (rm *ReloadManager) performReload(ctx context.Context) error {
	// Get updated config from lconfig
	updatedCfg, err := rm.lcfg.AsStruct()
	if err != nil {
		return fmt.Errorf("failed to get updated config: %w", err)
	}

	newCfg := updatedCfg.(*config.Config)

	// Get current service snapshot
	rm.mu.RLock()
	oldService := rm.service
	rm.mu.RUnlock()

	// Try to bootstrap with new configuration
	rm.logger.Debug("msg", "Bootstrapping new service with updated config")
	newService, err := bootstrapService(ctx, newCfg)
	if err != nil {
		// Bootstrap failed - keep old services running
		return fmt.Errorf("failed to bootstrap new service (old service still active): %w", err)
	}

	// Bootstrap succeeded - swap services atomically
	rm.mu.Lock()
	rm.service = newService
	rm.cfg = newCfg
	rm.mu.Unlock()

	// Stop old status reporter and start new one
	rm.restartStatusReporter(ctx, newService)

	// Gracefully shutdown old services
	// This happens after the swap to minimize downtime
	go rm.shutdownOldServices(oldService)

	return nil
}

// shutdownOldServices gracefully shuts down old services
func (rm *ReloadManager) shutdownOldServices(svc *service.Service) {
	// Give connections time to drain
	rm.logger.Debug("msg", "Draining connections from old services")
	time.Sleep(2 * time.Second)

	if svc != nil {
		rm.logger.Info("msg", "Shutting down old service")
		svc.Shutdown()
	}

	rm.logger.Debug("msg", "Old services shutdown complete")
}

// startStatusReporter starts a new status reporter
func (rm *ReloadManager) startStatusReporter(ctx context.Context, svc *service.Service) {
	rm.statusReporterMu.Lock()
	defer rm.statusReporterMu.Unlock()

	// Create cancellable context for status reporter
	reporterCtx, cancel := context.WithCancel(ctx)
	rm.statusReporterCancel = cancel

	go statusReporter(svc, reporterCtx)
	rm.logger.Debug("msg", "Started status reporter")
}

// restartStatusReporter stops old and starts new status reporter
func (rm *ReloadManager) restartStatusReporter(ctx context.Context, newService *service.Service) {
	if rm.cfg.DisableStatusReporter {
		// Just stop the old one if disabled
		rm.stopStatusReporter()
		return
	}

	rm.statusReporterMu.Lock()
	defer rm.statusReporterMu.Unlock()

	// Stop old reporter
	if rm.statusReporterCancel != nil {
		rm.statusReporterCancel()
		rm.logger.Debug("msg", "Stopped old status reporter")
	}

	// Start new reporter
	reporterCtx, cancel := context.WithCancel(ctx)
	rm.statusReporterCancel = cancel

	go statusReporter(newService, reporterCtx)
	rm.logger.Debug("msg", "Started new status reporter")
}

// stopStatusReporter stops the status reporter
func (rm *ReloadManager) stopStatusReporter() {
	rm.statusReporterMu.Lock()
	defer rm.statusReporterMu.Unlock()

	if rm.statusReporterCancel != nil {
		rm.statusReporterCancel()
		rm.statusReporterCancel = nil
		rm.logger.Debug("msg", "Stopped status reporter")
	}
}

// SaveConfig is a wrapper to save the config
func (rm *ReloadManager) SaveConfig(path string) error {
	if rm.lcfg == nil {
		return fmt.Errorf("no lconfig instance available")
	}
	return rm.lcfg.Save(path)
}

// Shutdown stops the reload manager
func (rm *ReloadManager) Shutdown() {
	rm.logger.Info("msg", "Shutting down reload manager")

	// Stop status reporter
	rm.stopStatusReporter()

	// Stop watching
	close(rm.shutdownCh)
	rm.wg.Wait()

	// Stop config watching
	if rm.lcfg != nil {
		rm.lcfg.StopAutoUpdate()
	}

	// Shutdown current services
	rm.mu.RLock()
	currentService := rm.service
	rm.mu.RUnlock()

	if currentService != nil {
		rm.logger.Info("msg", "Shutting down service")
		currentService.Shutdown()
	}
}

// GetService returns the current service (thread-safe)
func (rm *ReloadManager) GetService() *service.Service {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return rm.service
}