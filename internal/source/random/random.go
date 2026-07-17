package random

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"

	"logwisp/internal/config"
	"logwisp/internal/core"
	"logwisp/internal/plugin"
	"logwisp/internal/session"
	"logwisp/internal/source"

	lconfig "github.com/lixenwraith/config"
	"github.com/lixenwraith/log"
)

// init registers the component in plugin factory
func init() {
	if err := plugin.RegisterSource("random", NewRandomSourcePlugin); err != nil {
		panic(fmt.Sprintf("failed to register random source: %v", err))
	}
}

// RandomSource generates random log entries for testing
type RandomSource struct {
	// Plugin identity and session management
	id      string
	proxy   *session.Proxy
	session *session.Session

	// Configuration
	config *config.RandomSourceOptions

	// Application
	subscribers []chan core.LogEntry
	logger      *log.Logger
	rng         *rand.Rand
	mu          sync.RWMutex

	// Runtime
	done   chan struct{}
	wg     sync.WaitGroup
	cancel chan struct{}

	// Statistics
	totalEntries   atomic.Uint64
	droppedEntries atomic.Uint64
	startTime      time.Time
	lastEntryTime  atomic.Value // time.Time
}

const (
	DefaultRandomSourceIntervalMS = 500
	DefaultRandomSourceFormat     = "txt"
	DefaultRandomSourceLength     = 20
)

// NewRandomSourcePlugin creates a random source through plugin factory
func NewRandomSourcePlugin(
	id string,
	configMap map[string]any,
	logger *log.Logger,
	proxy *session.Proxy,
) (source.Source, error) {
	// Step 1: Create empty config struct with defaults
	opts := &config.RandomSourceOptions{
		IntervalMS: 500,
		JitterMS:   0,
		Format:     "txt",
		Length:     20,
		Special:    false,
	}

	// Scan config map
	if err := lconfig.ScanMap(configMap, opts); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	// Defaults
	if opts.IntervalMS <= 0 {
		opts.IntervalMS = DefaultRandomSourceIntervalMS
	}
	if opts.Format == "" {
		opts.Format = DefaultRandomSourceFormat
	}
	if opts.Length <= 0 {
		opts.Length = DefaultRandomSourceLength
	}

	// Validate
	if opts.JitterMS < 0 {
		return nil, fmt.Errorf("jitter_ms cannot be negative")
	}
	if opts.JitterMS > opts.IntervalMS {
		opts.JitterMS = opts.IntervalMS
	}

	validateFormat := lconfig.OneOf("raw", "txt", "json")
	if err := validateFormat(opts.Format); err != nil {
		return nil, fmt.Errorf("format: %w", err)
	}

	rs := &RandomSource{
		id:          id,
		proxy:       proxy,
		config:      opts,
		subscribers: make([]chan core.LogEntry, 0),
		done:        make(chan struct{}),
		cancel:      make(chan struct{}),
		logger:      logger,
		rng:         rand.New(rand.NewSource(time.Now().UnixNano())),
	}
	rs.lastEntryTime.Store(time.Time{})

	// Create session for random source
	rs.session = proxy.CreateSession(
		fmt.Sprintf("random://%s", id),
		map[string]any{
			"instance_id": id,
			"type":        "random",
			"format":      opts.Format,
			"interval_ms": opts.IntervalMS,
		},
	)

	logger.Debug("msg", "Random source initialized",
		"component", "random_source",
		"instance_id", id,
		"format", opts.Format,
		"interval_ms", opts.IntervalMS,
		"jitter_ms", opts.JitterMS)

	return rs, nil
}

// Capabilities returns supported capabilities
func (rs *RandomSource) Capabilities() []core.Capability {
	return []core.Capability{
		core.CapSessionAware,
	}
}

// Subscribe returns a channel for receiving log entries
func (rs *RandomSource) Subscribe() <-chan core.LogEntry {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	ch := make(chan core.LogEntry, 1000)
	rs.subscribers = append(rs.subscribers, ch)
	return ch
}

// Start begins generating random log entries
func (rs *RandomSource) Start() error {
	rs.startTime = time.Now()
	rs.wg.Add(1)
	go rs.generateLoop()

	rs.proxy.UpdateActivity(rs.session.ID)
	rs.logger.Debug("msg", "Random source started",
		"component", "random_source",
		"instance_id", rs.id)
	return nil
}

// Stop signals the source to stop generating
func (rs *RandomSource) Stop() {
	close(rs.cancel)
	rs.wg.Wait()

	if rs.session != nil {
		rs.proxy.RemoveSession(rs.session.ID)
	}

	rs.mu.Lock()
	for _, ch := range rs.subscribers {
		close(ch)
	}
	rs.mu.Unlock()

	rs.logger.Debug("msg", "Random source stopped",
		"component", "random_source",
		"instance_id", rs.id,
		"total_entries", rs.totalEntries.Load())
}

// GetStats returns the source's statistics
func (rs *RandomSource) GetStats() source.SourceStats {
	lastEntry, _ := rs.lastEntryTime.Load().(time.Time)

	return source.SourceStats{
		ID:             rs.id,
		Type:           "random",
		TotalEntries:   rs.totalEntries.Load(),
		DroppedEntries: rs.droppedEntries.Load(),
		StartTime:      rs.startTime,
		LastEntryTime:  lastEntry,
		Details: map[string]any{
			"format":      rs.config.Format,
			"interval_ms": rs.config.IntervalMS,
			"jitter_ms":   rs.config.JitterMS,
			"length":      rs.config.Length,
			"special":     rs.config.Special,
		},
	}
}

// generateLoop continuously generates random log entries at configured intervals
func (rs *RandomSource) generateLoop() {
	defer rs.wg.Done()

	for {
		// Calculate next interval with jitter
		interval := time.Duration(rs.config.IntervalMS) * time.Millisecond
		if rs.config.JitterMS > 0 {
			jitter := time.Duration(rs.rng.Intn(int(rs.config.JitterMS))) * time.Millisecond
			interval = interval - time.Duration(rs.config.JitterMS/2)*time.Millisecond + jitter
		}

		select {
		case <-time.After(interval):
			entry := rs.generateEntry()
			rs.publish(entry)
			rs.proxy.UpdateActivity(rs.session.ID)
		case <-rs.cancel:
			return
		case <-rs.done:
			return
		}
	}
}

// generateEntry creates a random log entry based on configured format
func (rs *RandomSource) generateEntry() core.LogEntry {
	now := time.Now()

	switch rs.config.Format {
	case "raw":
		message := rs.generateRandomString(int(rs.config.Length))
		return core.LogEntry{
			Time:    now,
			Source:  fmt.Sprintf("random_%s", rs.id),
			Message: message,
			RawSize: int64(len(message) + 1), // +1 for newline
		}

	case "txt":
		level := rs.randomLogLevel()
		message := rs.generateRandomString(int(rs.config.Length))
		formatted := fmt.Sprintf("[%s] [%s] random_%s - %s",
			now.Format(time.RFC3339),
			level,
			rs.id,
			message)
		return core.LogEntry{
			Time:    now,
			Source:  fmt.Sprintf("random_%s", rs.id),
			Level:   level,
			Message: formatted,
			RawSize: int64(len(formatted) + 1),
		}

	case "json":
		level := rs.randomLogLevel()
		message := rs.generateRandomString(int(rs.config.Length))
		data := map[string]any{
			"time":    now.Format(time.RFC3339Nano),
			"level":   level,
			"source":  fmt.Sprintf("random_%s", rs.id),
			"message": message,
		}
		jsonBytes, _ := json.Marshal(data)
		return core.LogEntry{
			Time:    now,
			Source:  fmt.Sprintf("random_%s", rs.id),
			Level:   level,
			Message: string(jsonBytes),
			RawSize: int64(len(jsonBytes) + 1),
		}

	default:
		return core.LogEntry{}
	}
}

// generateRandomString creates a random string of specified length
func (rs *RandomSource) generateRandomString(length int) string {
	const normalChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 "
	const specialChars = "\t\n\r\x00\x01\x02\x03\x04\x05\x06\x07\x08\x0B\x0C\x0E\x0F"
	const unicodeChars = "™€¢£¥§©®°±µ¶·ÀÉÑÖÜßäëïöü←↑→↓∀∃∅∇∈∉∪∩≈≠≤≥"

	result := make([]byte, 0, length)

	if rs.config.Special && length >= 3 {
		// Reserve space for at least one special and one unicode char
		normalLength := length - 2

		// Generate normal characters
		for i := 0; i < normalLength; i++ {
			result = append(result, normalChars[rs.rng.Intn(len(normalChars))])
		}

		// Insert special character at random position
		specialPos := rs.rng.Intn(len(result) + 1)
		specialChar := specialChars[rs.rng.Intn(len(specialChars))]
		result = append(result[:specialPos], append([]byte{specialChar}, result[specialPos:]...)...)

		// Insert unicode character at random position
		unicodePos := rs.rng.Intn(len(result) + 1)
		unicodeChar := unicodeChars[rs.rng.Intn(len(unicodeChars)/3)*3:]
		if len(unicodeChar) >= 3 {
			unicodeBytes := []byte(unicodeChar[:3])
			if unicodePos == len(result) {
				result = append(result, unicodeBytes...)
			} else {
				result = append(result[:unicodePos], append(unicodeBytes, result[unicodePos:]...)...)
			}
		}

		// Trim to exact length if needed
		if len(result) > length {
			result = result[:length]
		}
	} else {
		// Normal generation without special characters
		for i := 0; i < length; i++ {
			result = append(result, normalChars[rs.rng.Intn(len(normalChars))])
		}
	}

	return string(result)
}

// randomLogLevel returns a random log level
func (rs *RandomSource) randomLogLevel() string {
	levels := []string{"DEBUG", "INFO", "WARN", "ERROR"}
	return levels[rs.rng.Intn(len(levels))]
}

// publish sends a log entry to all subscribers
func (rs *RandomSource) publish(entry core.LogEntry) {
	rs.mu.RLock()
	defer rs.mu.RUnlock()

	rs.totalEntries.Add(1)
	rs.lastEntryTime.Store(entry.Time)

	for _, ch := range rs.subscribers {
		select {
		case ch <- entry:
		default:
			rs.droppedEntries.Add(1)
		}
	}
}