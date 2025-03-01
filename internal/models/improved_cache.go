package models

import (
	"sync"
	"time"
)

// CacheEntry merepresentasikan entri individual dalam cache dengan TTL
type CacheEntry struct {
	Data      interface{}
	ExpiresAt time.Time
}

// LRUCache adalah implementasi thread-safe LRU cache dengan TTL
type LRUCache struct {
	cache       map[string]CacheEntry
	mutex       *sync.RWMutex
	capacity    int
	accessOrder []string
	ttl         time.Duration
}

// NewLRUCache membuat instance baru LRUCache dengan kapasitas dan ttl tertentu
func NewLRUCache(capacity int, ttl time.Duration) *LRUCache {
	return &LRUCache{
		cache:       make(map[string]CacheEntry, capacity),
		mutex:       &sync.RWMutex{},
		capacity:    capacity,
		accessOrder: make([]string, 0, capacity),
		ttl:         ttl,
	}
}

// Set menyimpan nilai di cache
func (c *LRUCache) Set(key string, value interface{}) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// Jika key sudah ada, perbarui nilai dan pindahkan ke akhir access order
	if _, exists := c.cache[key]; exists {
		c.removeFromAccessOrder(key)
	} else if len(c.cache) >= c.capacity {
		// Jika cache penuh, hapus LRU item
		c.evictLRU()
	}

	// Tambahkan atau perbarui entri
	c.cache[key] = CacheEntry{
		Data:      value,
		ExpiresAt: time.Now().Add(c.ttl),
	}
	c.accessOrder = append(c.accessOrder, key)
}

// Get mengambil nilai dari cache, mengembalikan nil jika tidak ditemukan atau kadaluarsa
func (c *LRUCache) Get(key string) (interface{}, bool) {
	c.mutex.RLock()
	entry, exists := c.cache[key]
	c.mutex.RUnlock()

	if !exists {
		return nil, false
	}

	// Periksa apakah entri kadaluarsa
	if time.Now().After(entry.ExpiresAt) {
		c.mutex.Lock()
		delete(c.cache, key)
		c.removeFromAccessOrder(key)
		c.mutex.Unlock()
		return nil, false
	}

	// Perbarui access order
	c.mutex.Lock()
	c.removeFromAccessOrder(key)
	c.accessOrder = append(c.accessOrder, key)
	c.mutex.Unlock()

	return entry.Data, true
}

// Cleanup menghapus entri yang kadaluarsa
func (c *LRUCache) Cleanup() {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	now := time.Now()
	for key, entry := range c.cache {
		if now.After(entry.ExpiresAt) {
			delete(c.cache, key)
			c.removeFromAccessOrder(key)
		}
	}
}

// GetSize mengembalikan jumlah entri dalam cache
func (c *LRUCache) GetSize() int {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return len(c.cache)
}

// removeFromAccessOrder menghapus key dari daftar accessOrder
func (c *LRUCache) removeFromAccessOrder(key string) {
	for i, k := range c.accessOrder {
		if k == key {
			c.accessOrder = append(c.accessOrder[:i], c.accessOrder[i+1:]...)
			break
		}
	}
}

// evictLRU menghapus item yang paling tidak baru digunakan
func (c *LRUCache) evictLRU() {
	if len(c.accessOrder) == 0 {
		return
	}

	lruKey := c.accessOrder[0]
	delete(c.cache, lruKey)
	c.accessOrder = c.accessOrder[1:]
}

// NewDNSCacheWithLRU membuat DNS cache berbasis LRU
func NewDNSCacheWithLRU(capacity int, ttl time.Duration) *DNSCacheWithLRU {
	return &DNSCacheWithLRU{
		cache: NewLRUCache(capacity, ttl),
	}
}

// DNSCacheWithLRU mengimplementasikan cache DNS berbasis LRU
type DNSCacheWithLRU struct {
	cache *LRUCache
}

// Store menyimpan hasil DNS ke dalam cache
func (c *DNSCacheWithLRU) Store(subdomain string, result DNSResult) {
	c.cache.Set(subdomain, result)
}

// Load mengambil hasil DNS dari cache
func (c *DNSCacheWithLRU) Load(subdomain string) (DNSResult, bool) {
	val, ok := c.cache.Get(subdomain)
	if !ok {
		return DNSResult{}, false
	}
	return val.(DNSResult), true
}

// StartCleanup memulai pembersihan otomatis cache
func (c *DNSCacheWithLRU) StartCleanup(interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		for range ticker.C {
			c.cache.Cleanup()
		}
	}()
}
