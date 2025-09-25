// FILE: logwisp/src/internal/limit/token_bucket.go
package limit

import (
	"sync"
	"time"
)

// TokenBucket implements a token bucket rate limiter
// Safe for concurrent use.
type TokenBucket struct {
	capacity   float64
	tokens     float64
	refillRate float64 // tokens per second
	lastRefill time.Time
	mu         sync.Mutex
}

// Creates a new token bucket with given capacity and refill rate
func NewTokenBucket(capacity float64, refillRate float64) *TokenBucket {
	return &TokenBucket{
		capacity:   capacity,
		tokens:     capacity, // Start full
		refillRate: refillRate,
		lastRefill: time.Now(),
	}
}

// Attempts to consume one token, returns true if allowed
func (tb *TokenBucket) Allow() bool {
	return tb.AllowN(1)
}

// Attempts to consume n tokens, returns true if allowed
func (tb *TokenBucket) AllowN(n float64) bool {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	tb.refill()

	if tb.tokens >= n {
		tb.tokens -= n
		return true
	}
	return false
}

// Returns the current number of available tokens
func (tb *TokenBucket) Tokens() float64 {
	tb.mu.Lock()
	defer tb.mu.Unlock()

	tb.refill()
	return tb.tokens
}

// Adds tokens based on time elapsed since last refill
// MUST be called with mutex held
func (tb *TokenBucket) refill() {
	now := time.Now()
	elapsed := now.Sub(tb.lastRefill).Seconds()

	// Handle time sync issues causing negative elapsed time
	if elapsed < 0 {
		// Clock went backwards, reset to current time but don't add tokens
		tb.lastRefill = now
		elapsed = 0
	}

	tb.tokens += elapsed * tb.refillRate
	if tb.tokens > tb.capacity {
		tb.tokens = tb.capacity
	}
	tb.lastRefill = now
}