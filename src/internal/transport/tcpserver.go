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
	remoteAddr := c.RemoteAddr().String()
	s.streamer.logger.Debug("msg", "TCP connection attempt", "remote_addr", remoteAddr)

	// Check rate limit
	if s.streamer.rateLimiter != nil {
		// Parse the remote address to get proper net.Addr
		remoteStr := c.RemoteAddr().String()
		tcpAddr, err := net.ResolveTCPAddr("tcp", remoteStr)
		if err != nil {
			s.streamer.logger.Warn("msg", "Failed to parse TCP address",
				"remote_addr", remoteAddr,
				"error", err)
			return nil, gnet.Close
		}

		if !s.streamer.rateLimiter.CheckTCP(tcpAddr) {
			s.streamer.logger.Warn("msg", "TCP connection rate limited",
				"remote_addr", remoteAddr)
			// Silently close connection when rate limited
			return nil, gnet.Close
		}

		// Track connection
		s.streamer.rateLimiter.AddConnection(remoteStr)
	}

	s.connections.Store(c, struct{}{})

	newCount := s.streamer.activeConns.Add(1)
	s.streamer.logger.Debug("msg", "TCP connection opened",
		"remote_addr", remoteAddr,
		"active_connections", newCount)

	return nil, gnet.None
}

func (s *tcpServer) OnClose(c gnet.Conn, err error) gnet.Action {
	s.connections.Delete(c)

	remoteAddr := c.RemoteAddr().String()

	// Remove connection tracking
	if s.streamer.rateLimiter != nil {
		s.streamer.rateLimiter.RemoveConnection(c.RemoteAddr().String())
	}

	newCount := s.streamer.activeConns.Add(-1)
	s.streamer.logger.Debug("msg", "TCP connection closed",
		"remote_addr", remoteAddr,
		"active_connections", newCount,
		"error", err)
	return gnet.None
}

func (s *tcpServer) OnTraffic(c gnet.Conn) gnet.Action {
	// We don't expect input from clients, just discard
	c.Discard(-1)
	return gnet.None
}