package random

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lixenwraith/logwisp/internal/config"
	"github.com/lixenwraith/logwisp/internal/core"
	"github.com/lixenwraith/logwisp/internal/plugin"
	"github.com/lixenwraith/logwisp/internal/session"
	"github.com/lixenwraith/logwisp/internal/source"

	"github.com/lixenwraith/log"
)

func init() {
	if err := plugin.RegisterSource("random", NewRandomSourcePlugin); err != nil {
		panic(fmt.Sprintf("failed to register random source: %v", err))
	}
}

// RandomSource generates entries, to check a deployment before real logs are wired
type RandomSource struct {
	id      string
	proxy   *session.Proxy
	session *session.Session

	config *config.RandomSourceOptions

	subscribers []chan core.LogEntry
	logger      *log.Logger
	rng         *rand.Rand
	mu          sync.RWMutex

	done   chan struct{}
	wg     sync.WaitGroup
	cancel chan struct{}

	totalEntries   atomic.Uint64
	droppedEntries atomic.Uint64
	startTime      time.Time
	lastEntryTime  atomic.Value // time.Time
}

func NewRandomSourcePlugin(
	id string,
	configMap map[string]any,
	logger *log.Logger,
	proxy *session.Proxy,
) (source.Source, error) {
	opts, err := config.Decode[config.RandomSourceOptions]("source", "random", configMap)
	if err != nil {
		return nil, err
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

func (rs *RandomSource) Capabilities() []core.Capability {
	return []core.Capability{
		core.CapSessionAware,
	}
}

func (rs *RandomSource) Subscribe() <-chan core.LogEntry {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	ch := make(chan core.LogEntry, 1000)
	rs.subscribers = append(rs.subscribers, ch)
	return ch
}

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

func (rs *RandomSource) generateLoop() {
	defer rs.wg.Done()

	for {
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

func (rs *RandomSource) generateRandomString(length int) string {
	const normalChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 "
	const specialChars = "\t\n\r\x00\x01\x02\x03\x04\x05\x06\x07\x08\x0B\x0C\x0E\x0F"
	const unicodeChars = "™€¢£¥§©®°±µ¶·ÀÉÑÖÜßäëïöü←↑→↓∀∃∅∇∈∉∪∩≈≠≤≥"

	result := make([]byte, 0, length)

	if rs.config.Special && length >= 3 {
		// Reserve space for at least one special and one unicode char
		normalLength := length - 2

		for i := 0; i < normalLength; i++ {
			result = append(result, normalChars[rs.rng.Intn(len(normalChars))])
		}

		specialPos := rs.rng.Intn(len(result) + 1)
		specialChar := specialChars[rs.rng.Intn(len(specialChars))]
		result = append(result[:specialPos], append([]byte{specialChar}, result[specialPos:]...)...)

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

		if len(result) > length {
			result = result[:length]
		}
	} else {
		for i := 0; i < length; i++ {
			result = append(result, normalChars[rs.rng.Intn(len(normalChars))])
		}
	}

	return string(result)
}

func (rs *RandomSource) randomLogLevel() string {
	levels := []string{"DEBUG", "INFO", "WARN", "ERROR"}
	return levels[rs.rng.Intn(len(levels))]
}

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
