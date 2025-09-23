// FILE: src/internal/tls/gnet_bridge.go
package tls

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/panjf2000/gnet/v2"
)

var (
	ErrTLSBackpressure         = errors.New("TLS processing backpressure")
	ErrConnectionClosed        = errors.New("connection closed")
	ErrPlaintextBufferExceeded = errors.New("plaintext buffer size exceeded")
)

// Maximum plaintext buffer size to prevent memory exhaustion
const maxPlaintextBufferSize = 32 * 1024 * 1024 // 32MB

// GNetTLSConn bridges gnet.Conn with crypto/tls via io.Pipe
type GNetTLSConn struct {
	gnetConn gnet.Conn
	tlsConn  *tls.Conn
	config   *tls.Config

	// Buffered channels for non-blocking operation
	incomingCipher chan []byte // Network → TLS (encrypted)
	outgoingCipher chan []byte // TLS → Network (encrypted)

	// Handshake state
	handshakeOnce sync.Once
	handshakeDone chan struct{}
	handshakeErr  error

	// Decrypted data buffer
	plainBuf []byte
	plainMu  sync.Mutex

	// Lifecycle
	closed    atomic.Bool
	closeOnce sync.Once
	wg        sync.WaitGroup

	// Error tracking
	lastErr atomic.Value                   // error
	logger  interface{ Warn(args ...any) } // Minimal logger interface
}

// NewServerConn creates a server-side TLS bridge
func NewServerConn(gnetConn gnet.Conn, config *tls.Config) *GNetTLSConn {
	tc := &GNetTLSConn{
		gnetConn:      gnetConn,
		config:        config,
		handshakeDone: make(chan struct{}),
		// Buffered channels sized for throughput without blocking
		incomingCipher: make(chan []byte, 128), // 128 packets buffer
		outgoingCipher: make(chan []byte, 128),
		plainBuf:       make([]byte, 0, 65536), // 64KB initial capacity
	}

	// Create TLS conn with channel-based transport
	rawConn := &channelConn{
		incoming:   tc.incomingCipher,
		outgoing:   tc.outgoingCipher,
		localAddr:  gnetConn.LocalAddr(),
		remoteAddr: gnetConn.RemoteAddr(),
		tc:         tc,
	}
	tc.tlsConn = tls.Server(rawConn, config)

	// Start pump goroutines
	tc.wg.Add(2)
	go tc.pumpCipherToNetwork()
	go tc.pumpPlaintextFromTLS()

	return tc
}

// NewClientConn creates a client-side TLS bridge (similar changes)
func NewClientConn(gnetConn gnet.Conn, config *tls.Config, serverName string) *GNetTLSConn {
	tc := &GNetTLSConn{
		gnetConn:       gnetConn,
		config:         config,
		handshakeDone:  make(chan struct{}),
		incomingCipher: make(chan []byte, 128),
		outgoingCipher: make(chan []byte, 128),
		plainBuf:       make([]byte, 0, 65536),
	}

	if config.ServerName == "" {
		config = config.Clone()
		config.ServerName = serverName
	}

	rawConn := &channelConn{
		incoming:   tc.incomingCipher,
		outgoing:   tc.outgoingCipher,
		localAddr:  gnetConn.LocalAddr(),
		remoteAddr: gnetConn.RemoteAddr(),
		tc:         tc,
	}
	tc.tlsConn = tls.Client(rawConn, config)

	tc.wg.Add(2)
	go tc.pumpCipherToNetwork()
	go tc.pumpPlaintextFromTLS()

	return tc
}

// ProcessIncoming feeds encrypted data from network into TLS engine (non-blocking)
func (tc *GNetTLSConn) ProcessIncoming(encryptedData []byte) error {
	if tc.closed.Load() {
		return ErrConnectionClosed
	}

	// Non-blocking send with backpressure detection
	select {
	case tc.incomingCipher <- encryptedData:
		return nil
	default:
		// Channel full - TLS processing can't keep up
		// Drop connection under backpressure vs blocking event loop
		if tc.logger != nil {
			tc.logger.Warn("msg", "TLS backpressure, dropping data",
				"remote_addr", tc.gnetConn.RemoteAddr())
		}
		return ErrTLSBackpressure
	}
}

// pumpCipherToNetwork sends TLS-encrypted data to network
func (tc *GNetTLSConn) pumpCipherToNetwork() {
	defer tc.wg.Done()

	for {
		select {
		case data, ok := <-tc.outgoingCipher:
			if !ok {
				return
			}
			// Send to network
			if err := tc.gnetConn.AsyncWrite(data, nil); err != nil {
				tc.lastErr.Store(err)
				tc.Close()
				return
			}
		case <-time.After(30 * time.Second):
			// Keepalive/timeout check
			if tc.closed.Load() {
				return
			}
		}
	}
}

// pumpPlaintextFromTLS reads decrypted data from TLS
func (tc *GNetTLSConn) pumpPlaintextFromTLS() {
	defer tc.wg.Done()
	buf := make([]byte, 32768) // 32KB read buffer

	for {
		n, err := tc.tlsConn.Read(buf)
		if n > 0 {
			tc.plainMu.Lock()
			// Check buffer size limit before appending to prevent memory exhaustion
			if len(tc.plainBuf)+n > maxPlaintextBufferSize {
				tc.plainMu.Unlock()
				// Log warning about buffer limit
				if tc.logger != nil {
					tc.logger.Warn("msg", "Plaintext buffer limit exceeded, closing connection",
						"remote_addr", tc.gnetConn.RemoteAddr(),
						"buffer_size", len(tc.plainBuf),
						"incoming_size", n,
						"limit", maxPlaintextBufferSize)
				}
				// Store error and close connection
				tc.lastErr.Store(ErrPlaintextBufferExceeded)
				tc.Close()
				return
			}
			tc.plainBuf = append(tc.plainBuf, buf[:n]...)
			tc.plainMu.Unlock()
		}
		if err != nil {
			if err != io.EOF {
				tc.lastErr.Store(err)
			}
			tc.Close()
			return
		}
	}
}

// Read returns available decrypted plaintext (non-blocking)
func (tc *GNetTLSConn) Read() []byte {
	tc.plainMu.Lock()
	defer tc.plainMu.Unlock()

	if len(tc.plainBuf) == 0 {
		return nil
	}

	// Atomic buffer swap under mutex protection to prevent race condition
	data := tc.plainBuf
	tc.plainBuf = make([]byte, 0, cap(tc.plainBuf))
	return data
}

// Write encrypts plaintext and queues for network transmission
func (tc *GNetTLSConn) Write(plaintext []byte) (int, error) {
	if tc.closed.Load() {
		return 0, ErrConnectionClosed
	}

	if !tc.IsHandshakeDone() {
		return 0, errors.New("handshake not complete")
	}

	return tc.tlsConn.Write(plaintext)
}

// Handshake initiates TLS handshake asynchronously
func (tc *GNetTLSConn) Handshake() {
	tc.handshakeOnce.Do(func() {
		go func() {
			tc.handshakeErr = tc.tlsConn.Handshake()
			close(tc.handshakeDone)
		}()
	})
}

// IsHandshakeDone checks if handshake is complete
func (tc *GNetTLSConn) IsHandshakeDone() bool {
	select {
	case <-tc.handshakeDone:
		return true
	default:
		return false
	}
}

// HandshakeComplete waits for handshake completion
func (tc *GNetTLSConn) HandshakeComplete() (<-chan struct{}, error) {
	<-tc.handshakeDone
	return tc.handshakeDone, tc.handshakeErr
}

// Close shuts down the bridge
func (tc *GNetTLSConn) Close() error {
	tc.closeOnce.Do(func() {
		tc.closed.Store(true)

		// Close TLS connection
		tc.tlsConn.Close()

		// Close channels to stop pumps
		close(tc.incomingCipher)
		close(tc.outgoingCipher)
	})

	// Wait for pumps to finish
	tc.wg.Wait()
	return nil
}

// GetConnectionState returns TLS connection state
func (tc *GNetTLSConn) GetConnectionState() tls.ConnectionState {
	return tc.tlsConn.ConnectionState()
}

// GetError returns last error
func (tc *GNetTLSConn) GetError() error {
	if err, ok := tc.lastErr.Load().(error); ok {
		return err
	}
	return nil
}

// channelConn implements net.Conn over channels
type channelConn struct {
	incoming   <-chan []byte
	outgoing   chan<- []byte
	localAddr  net.Addr
	remoteAddr net.Addr
	tc         *GNetTLSConn
	readBuf    []byte
}

func (c *channelConn) Read(b []byte) (int, error) {
	// Use buffered read for efficiency
	if len(c.readBuf) > 0 {
		n := copy(b, c.readBuf)
		c.readBuf = c.readBuf[n:]
		return n, nil
	}

	// Wait for new data
	select {
	case data, ok := <-c.incoming:
		if !ok {
			return 0, io.EOF
		}
		n := copy(b, data)
		if n < len(data) {
			c.readBuf = data[n:] // Buffer remainder
		}
		return n, nil
	case <-time.After(30 * time.Second):
		return 0, errors.New("read timeout")
	}
}

func (c *channelConn) Write(b []byte) (int, error) {
	if c.tc.closed.Load() {
		return 0, ErrConnectionClosed
	}

	// Make a copy since TLS may hold reference
	data := make([]byte, len(b))
	copy(data, b)

	select {
	case c.outgoing <- data:
		return len(b), nil
	case <-time.After(5 * time.Second):
		return 0, errors.New("write timeout")
	}
}

func (c *channelConn) Close() error                       { return nil }
func (c *channelConn) LocalAddr() net.Addr                { return c.localAddr }
func (c *channelConn) RemoteAddr() net.Addr               { return c.remoteAddr }
func (c *channelConn) SetDeadline(t time.Time) error      { return nil }
func (c *channelConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *channelConn) SetWriteDeadline(t time.Time) error { return nil }