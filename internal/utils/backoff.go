package utils

import (
	"math"
	"math/rand"
	"sync"
	"time"
)

// ExponentialBackoff implementation of exponential backoff algorithm with jitter
// for adaptive rate limiting
type ExponentialBackoff struct {
	baseDelay    time.Duration
	maxDelay     time.Duration
	factor       float64
	jitter       float64
	attemptsMap  map[string]int
	targetCounts map[string]int
	mutex        sync.RWMutex
	rnd          *rand.Rand
}

// NewExponentialBackoff creates a new instance of ExponentialBackoff
func NewExponentialBackoff(baseDelay, maxDelay time.Duration, factor, jitter float64) *ExponentialBackoff {
	return &ExponentialBackoff{
		baseDelay:    baseDelay,
		maxDelay:     maxDelay,
		factor:       factor,
		jitter:       jitter,
		attemptsMap:  make(map[string]int),
		targetCounts: make(map[string]int),
		rnd:          rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

// NextDelay calculates the next delay based on target and number of attempts
func (b *ExponentialBackoff) NextDelay(target string) time.Duration {
	b.mutex.Lock()
	defer b.mutex.Unlock()

	// Increment attempt counter for this target
	b.attemptsMap[target]++
	attempts := b.attemptsMap[target]

	// Increment request count for this target
	b.targetCounts[target]++

	// Calculate delay
	delay := float64(b.baseDelay) * math.Pow(b.factor, float64(attempts-1))

	// Add jitter
	jitterVal := b.rnd.Float64() * b.jitter * delay
	delay += jitterVal

	// Cap at max delay
	if delay > float64(b.maxDelay) {
		delay = float64(b.maxDelay)
	}

	return time.Duration(delay)
}

// Reset resets the attempt counter for a specific target
func (b *ExponentialBackoff) Reset(target string) {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	b.attemptsMap[target] = 0
}

// ResetAll resets all attempt counters
func (b *ExponentialBackoff) ResetAll() {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	b.attemptsMap = make(map[string]int)
}

// GetRequestCount returns the number of requests made to a specific target
func (b *ExponentialBackoff) GetRequestCount(target string) int {
	b.mutex.RLock()
	defer b.mutex.RUnlock()
	return b.targetCounts[target]
}

// IsRateLimited checks if a target exceeds the request limit
// and requires a longer delay
func (b *ExponentialBackoff) IsRateLimited(target string, threshold int) bool {
	b.mutex.RLock()
	defer b.mutex.RUnlock()
	return b.attemptsMap[target] >= threshold
}

// AdaptiveDelay calculates delay based on target response
// If failure occurs, backoff increases. If successful, backoff gradually decreases.
func (b *ExponentialBackoff) AdaptiveDelay(target string, success bool) time.Duration {
	if success {
		// If successful, reduce attempt counter (with lower bound of 0)
		b.mutex.Lock()
		if b.attemptsMap[target] > 0 {
			b.attemptsMap[target]--
		}
		attempts := b.attemptsMap[target]
		b.mutex.Unlock()

		// Calculate delay based on reduced counter
		delay := float64(b.baseDelay) * math.Pow(b.factor, float64(attempts))
		return time.Duration(delay)
	} else {
		// If failed, use normal exponential backoff
		return b.NextDelay(target)
	}
}
