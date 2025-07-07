// FILE: src/internal/monitor/tcpserver.go
package stream

import (
	"fmt"
	"github.com/panjf2000/gnet/v2"
	"sync"
)

type tcpServer struct {
	gnet.BuiltinEventEngine
	streamer    *TCPStreamer
	connections sync.Map
}

func (s *tcpServer) OnBoot(eng gnet.Engine) gnet.Action {
	// Store engine reference for shutdown
	s.streamer.engine = &eng
	return gnet.None
}

func (s *tcpServer) OnOpen(c gnet.Conn) (out []byte, action gnet.Action) {
	s.connections.Store(c, struct{}{})

	oldCount := s.streamer.activeConns.Load()
	newCount := s.streamer.activeConns.Add(1)
	fmt.Printf("[TCP ATOMIC] OnOpen: %d -> %d (expected: %d)\n", oldCount, newCount, oldCount+1)

	fmt.Printf("[TCP DEBUG] Connection opened. Count now: %d\n", newCount)
	return nil, gnet.None
}

func (s *tcpServer) OnClose(c gnet.Conn, err error) gnet.Action {
	s.connections.Delete(c)

	oldCount := s.streamer.activeConns.Load()
	newCount := s.streamer.activeConns.Add(-1)
	fmt.Printf("[TCP ATOMIC] OnClose: %d -> %d (expected: %d)\n", oldCount, newCount, oldCount-1)

	fmt.Printf("[TCP DEBUG] Connection closed. Count now: %d (err: %v)\n", newCount, err)
	return gnet.None
}

func (s *tcpServer) OnTraffic(c gnet.Conn) gnet.Action {
	// We don't expect input from clients, just discard
	c.Discard(-1)
	return gnet.None
}

func (t *TCPStreamer) GetActiveConnections() int32 {
	return t.activeConns.Load()
}