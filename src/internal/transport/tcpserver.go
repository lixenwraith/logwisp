// FILE: src/internal/monitor/tcpserver.go
package transport

import (
	"fmt"
	"net"
	"sync"

	"github.com/panjf2000/gnet/v2"
)

type tcpServer struct {
	gnet.BuiltinEventEngine
	streamer    *TCPStreamer
	connections sync.Map
}

func (s *tcpServer) OnBoot(eng gnet.Engine) gnet.Action {
	// Store engine reference for shutdown
	s.streamer.engineMu.Lock()
	s.streamer.engine = &eng
	s.streamer.engineMu.Unlock()

	fmt.Printf("[TCP DEBUG] Server booted on port %d\n", s.streamer.config.Port)
	return gnet.None
}

func (s *tcpServer) OnOpen(c gnet.Conn) (out []byte, action gnet.Action) {
	// Debug: Log all connection attempts
	fmt.Printf("[TCP DEBUG] Connection attempt from %s\n", c.RemoteAddr())

	// Check rate limit
	if s.streamer.rateLimiter != nil {
		// Parse the remote address to get proper net.Addr
		remoteStr := c.RemoteAddr().String()
		tcpAddr, err := net.ResolveTCPAddr("tcp", remoteStr)
		if err != nil {
			fmt.Printf("[TCP DEBUG] Failed to parse address %s: %v\n", remoteStr, err)
			return nil, gnet.Close
		}

		if !s.streamer.rateLimiter.CheckTCP(tcpAddr) {
			fmt.Printf("[TCP DEBUG] Rate limited connection from %s\n", remoteStr)
			// Silently close connection when rate limited
			return nil, gnet.Close
		}

		// Track connection
		s.streamer.rateLimiter.AddConnection(remoteStr)
	}

	s.connections.Store(c, struct{}{})

	oldCount := s.streamer.activeConns.Load()
	newCount := s.streamer.activeConns.Add(1)
	fmt.Printf("[TCP ATOMIC] OnOpen: %d -> %d (expected: %d)\n", oldCount, newCount, oldCount+1)

	fmt.Printf("[TCP DEBUG] Connection opened. Count now: %d\n", newCount)
	return nil, gnet.None
}

func (s *tcpServer) OnClose(c gnet.Conn, err error) gnet.Action {
	s.connections.Delete(c)

	// Remove connection tracking
	if s.streamer.rateLimiter != nil {
		s.streamer.rateLimiter.RemoveConnection(c.RemoteAddr().String())
	}

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