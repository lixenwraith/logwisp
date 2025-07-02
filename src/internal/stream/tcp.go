// FILE: src/internal/stream/tcp.go
package stream

import (
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
}

type tcpServer struct {
	gnet.BuiltinEventEngine
	streamer    *TCPStreamer
	connections sync.Map
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
	go t.broadcastLoop()

	// Configure gnet with no-op logger
	addr := fmt.Sprintf("tcp://:%d", t.config.Port)

	err := gnet.Run(t.server, addr,
		gnet.WithLogger(noopLogger{}), // No-op logger: discard everything
		gnet.WithMulticore(true),
		gnet.WithReusePort(true),
	)

	return err
}

func (t *TCPStreamer) Stop() {
	close(t.done)
	// No engine to stop with gnet v2
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
		case entry := <-t.logChan:
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

func (s *tcpServer) OnBoot(eng gnet.Engine) gnet.Action {
	return gnet.None
}

func (s *tcpServer) OnOpen(c gnet.Conn) (out []byte, action gnet.Action) {
	s.connections.Store(c, struct{}{})
	s.streamer.activeConns.Add(1)
	return nil, gnet.None
}

func (s *tcpServer) OnClose(c gnet.Conn, err error) gnet.Action {
	s.connections.Delete(c)
	s.streamer.activeConns.Add(-1)
	return gnet.None
}

func (s *tcpServer) OnTraffic(c gnet.Conn) gnet.Action {
	// We don't expect input from clients, just discard
	c.Discard(-1)
	return gnet.None
}