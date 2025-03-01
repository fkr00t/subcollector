package utils

import (
	"math"
	"math/rand"
	"sync"
	"time"
)

// ExponentialBackoff implementasi algoritma backoff eksponensial dengan jitter
// untuk rate limiting yang adaptif
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

// NewExponentialBackoff membuat instance baru dari ExponentialBackoff
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

// NextDelay menghitung penundaan berikutnya berdasarkan target dan jumlah percobaan
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

// Reset mengatur ulang counter percobaan untuk target tertentu
func (b *ExponentialBackoff) Reset(target string) {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	b.attemptsMap[target] = 0
}

// ResetAll mengatur ulang semua counter percobaan
func (b *ExponentialBackoff) ResetAll() {
	b.mutex.Lock()
	defer b.mutex.Unlock()
	b.attemptsMap = make(map[string]int)
}

// GetRequestCount mengembalikan jumlah permintaan yang dibuat ke target tertentu
func (b *ExponentialBackoff) GetRequestCount(target string) int {
	b.mutex.RLock()
	defer b.mutex.RUnlock()
	return b.targetCounts[target]
}

// IsRateLimited memeriksa apakah target melebihi batas permintaan
// dan memerlukan penundaan yang lebih lama
func (b *ExponentialBackoff) IsRateLimited(target string, threshold int) bool {
	b.mutex.RLock()
	defer b.mutex.RUnlock()
	return b.attemptsMap[target] >= threshold
}

// AdaptiveDelay menghitung penundaan berdasarkan respons target
// Jika terjadi kegagalan, backoff meningkat. Jika berhasil, backoff berkurang secara bertahap.
func (b *ExponentialBackoff) AdaptiveDelay(target string, success bool) time.Duration {
	if success {
		// Jika berhasil, kurangi counter percobaan (dengan batas bawah 0)
		b.mutex.Lock()
		if b.attemptsMap[target] > 0 {
			b.attemptsMap[target]--
		}
		attempts := b.attemptsMap[target]
		b.mutex.Unlock()

		// Hitung penundaan berdasarkan counter yang dikurangi
		delay := float64(b.baseDelay) * math.Pow(b.factor, float64(attempts))
		return time.Duration(delay)
	} else {
		// Jika gagal, gunakan penundaan eksponensial normal
		return b.NextDelay(target)
	}
}
