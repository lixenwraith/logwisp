// File: logwisp/src/internal/middleware/ratelimit.go
package middleware

import (
	"fmt"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// RateLimiter provides per-client rate limiting
type RateLimiter struct {
	clients         sync.Map // map[string]*clientLimiter
	requestsPerSec  int
	burstSize       int
	cleanupInterval time.Duration
	done            chan struct{}
}

type clientLimiter struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// NewRateLimiter creates a new rate limiting middleware
func NewRateLimiter(requestsPerSec, burstSize int, cleanupIntervalSec int64) *RateLimiter {
	rl := &RateLimiter{
		requestsPerSec:  requestsPerSec,
		burstSize:       burstSize,
		cleanupInterval: time.Duration(cleanupIntervalSec) * time.Second,
		done:            make(chan struct{}),
	}

	// Start cleanup routine
	go rl.cleanup()

	return rl
}

// Middleware returns an HTTP middleware function
func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get client IP
		clientIP := r.RemoteAddr
		if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
			clientIP = forwarded
		}

		// Get or create limiter for client
		limiter := rl.getLimiter(clientIP)

		// Check rate limit
		if !limiter.Allow() {
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		// Continue to next handler
		next.ServeHTTP(w, r)
	})
}

// getLimiter returns the rate limiter for a client
func (rl *RateLimiter) getLimiter(clientIP string) *rate.Limiter {
	// Try to get existing limiter
	if val, ok := rl.clients.Load(clientIP); ok {
		client := val.(*clientLimiter)
		client.lastSeen = time.Now()
		return client.limiter
	}

	// Create new limiter
	limiter := rate.NewLimiter(rate.Limit(rl.requestsPerSec), rl.burstSize)
	client := &clientLimiter{
		limiter:  limiter,
		lastSeen: time.Now(),
	}

	rl.clients.Store(clientIP, client)
	return limiter
}

// cleanup removes old client limiters
func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(rl.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-rl.done:
			return
		case <-ticker.C:
			rl.removeOldClients()
		}
	}
}

// removeOldClients removes limiters that haven't been seen recently
func (rl *RateLimiter) removeOldClients() {
	threshold := time.Now().Add(-rl.cleanupInterval * 2) // Keep for 2x cleanup interval

	rl.clients.Range(func(key, value interface{}) bool {
		client := value.(*clientLimiter)
		if client.lastSeen.Before(threshold) {
			rl.clients.Delete(key)
		}
		return true
	})
}

// Stop gracefully shuts down the rate limiter
func (rl *RateLimiter) Stop() {
	close(rl.done)
}

// Stats returns current rate limiter statistics
func (rl *RateLimiter) Stats() string {
	count := 0
	rl.clients.Range(func(_, _ interface{}) bool {
		count++
		return true
	})
	return fmt.Sprintf("Active clients: %d", count)
}