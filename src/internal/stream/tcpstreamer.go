// FILE: src/internal/stream/tcpstreamer.go
package stream

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/panjf2000/gnet/v2"
	"logwisp/src/internal/config"
	"logwisp/src/internal/monitor"
)

type TCPStreamer struct {
	logChan     chan monitor.LogEntry
	config      config.TCPConfig
	server      *tcpServer
	done        chan struct{}
	activeConns atomic.Int32
	startTime   time.Time
	engine      *gnet.Engine
	wg          sync.WaitGroup
}

func NewTCPStreamer(logChan chan monitor.LogEntry, cfg config.TCPConfig) *TCPStreamer {
	return &TCPStreamer{
		logChan:   logChan,
		config:    cfg,
		done:      make(chan struct{}),
		startTime: time.Now(),
	}
}

func (t *TCPStreamer) Start() error {
	t.server = &tcpServer{streamer: t}

	// Start log broadcast loop
	t.wg.Add(1)
	go func() {
		defer t.wg.Done()
		t.broadcastLoop()
	}()

	// Configure gnet
	addr := fmt.Sprintf("tcp://:%d", t.config.Port)

	// Run gnet in separate goroutine to avoid blocking
	errChan := make(chan error, 1)
	go func() {
		err := gnet.Run(t.server, addr,
			gnet.WithLogger(noopLogger{}),
			gnet.WithMulticore(true),
			gnet.WithReusePort(true),
		)
		errChan <- err
	}()

	// Wait briefly for server to start or fail
	select {
	case err := <-errChan:
		// Server failed immediately
		close(t.done)
		t.wg.Wait()
		return err
	case <-time.After(100 * time.Millisecond):
		// Server started successfully
		return nil
	}
}

func (t *TCPStreamer) Stop() {
	// Signal broadcast loop to stop
	close(t.done)

	// Stop gnet engine if running
	if t.engine != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		t.engine.Stop(ctx)
	}

	// Wait for broadcast loop to finish
	t.wg.Wait()
}

func (t *TCPStreamer) broadcastLoop() {
	var ticker *time.Ticker
	var tickerChan <-chan time.Time

	if t.config.Heartbeat.Enabled {
		ticker = time.NewTicker(time.Duration(t.config.Heartbeat.IntervalSeconds) * time.Second)
		tickerChan = ticker.C
		defer ticker.Stop()
	}

	for {
		select {
		case entry, ok := <-t.logChan:
			if !ok {
				return
			}
			data, err := json.Marshal(entry)
			if err != nil {
				continue
			}
			data = append(data, '\n')

			t.server.connections.Range(func(key, value interface{}) bool {
				conn := key.(gnet.Conn)
				conn.AsyncWrite(data, nil)
				return true
			})

		case <-tickerChan:
			if heartbeat := t.formatHeartbeat(); heartbeat != nil {
				t.server.connections.Range(func(key, value interface{}) bool {
					conn := key.(gnet.Conn)
					conn.AsyncWrite(heartbeat, nil)
					return true
				})
			}

		case <-t.done:
			return
		}
	}
}

func (t *TCPStreamer) formatHeartbeat() []byte {
	if !t.config.Heartbeat.Enabled {
		return nil
	}

	data := make(map[string]interface{})
	data["type"] = "heartbeat"

	if t.config.Heartbeat.IncludeTimestamp {
		data["time"] = time.Now().UTC().Format(time.RFC3339Nano)
	}

	if t.config.Heartbeat.IncludeStats {
		data["active_connections"] = t.activeConns.Load()
		data["uptime_seconds"] = int(time.Since(t.startTime).Seconds())
	}

	jsonData, _ := json.Marshal(data)
	return append(jsonData, '\n')
}