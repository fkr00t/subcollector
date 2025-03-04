package models

import (
	"sync"
	"time"
)

// DNSResult represents the result of a DNS lookup, used in caching
type DNSResult struct {
	Found bool     // Indicates if the subdomain exists
	IPs   []string // Associated IP addresses if the subdomain is found
}

//
// Basic DNS Cache Implementation
//

// DNSCache provides a thread-safe cache for DNS results using sync.Map
type DNSCache struct {
	cache *sync.Map
}

// NewDNSCache creates a new instance of DNSCache
func NewDNSCache() *DNSCache {
	return &DNSCache{
		cache: &sync.Map{},
	}
}

// Store saves the DNS result in the cache
func (c *DNSCache) Store(subdomain string, result DNSResult) {
	c.cache.Store(subdomain, result)
}

// Load retrieves a DNS result from the cache
func (c *DNSCache) Load(subdomain string) (DNSResult, bool) {
	val, ok := c.cache.Load(subdomain)
	if !ok {
		return DNSResult{}, false
	}
	return val.(DNSResult), true
}

//
// Advanced LRU Cache Implementation with TTL
//

// CacheEntry represents an individual cache entry with TTL
type CacheEntry struct {
	Data      interface{}
	ExpiresAt time.Time
}

// LRUCache is a thread-safe implementation of an LRU cache with TTL
type LRUCache struct {
	cache       map[string]CacheEntry
	mutex       *sync.RWMutex
	capacity    int
	accessOrder []string
	ttl         time.Duration
}

// NewLRUCache creates a new instance of LRUCache with a specified capacity and TTL
func NewLRUCache(capacity int, ttl time.Duration) *LRUCache {
	return &LRUCache{
		cache:       make(map[string]CacheEntry, capacity),
		mutex:       &sync.RWMutex{},
		capacity:    capacity,
		accessOrder: make([]string, 0, capacity),
		ttl:         ttl,
	}
}

// Set stores a value in the cache
func (c *LRUCache) Set(key string, value interface{}) {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// If the key exists, update the value and move it to the end of access order
	if _, exists := c.cache[key]; exists {
		c.removeFromAccessOrder(key)
	} else if len(c.cache) >= c.capacity {
		// If the cache is full, evict the LRU item
		c.evictLRU()
	}

	// Add or update entry
	c.cache[key] = CacheEntry{
		Data:      value,
		ExpiresAt: time.Now().Add(c.ttl),
	}
	c.accessOrder = append(c.accessOrder, key)
}

// Get retrieves a value from the cache, returning nil if not found or expired
func (c *LRUCache) Get(key string) (interface{}, bool) {
	c.mutex.RLock()
	entry, exists := c.cache[key]
	c.mutex.RUnlock()

	if !exists {
		return nil, false
	}

	// Check if the entry is expired
	if time.Now().After(entry.ExpiresAt) {
		c.mutex.Lock()
		delete(c.cache, key)
		c.removeFromAccessOrder(key)
		c.mutex.Unlock()
		return nil, false
	}

	// Update access order
	c.mutex.Lock()
	c.removeFromAccessOrder(key)
	c.accessOrder = append(c.accessOrder, key)
	c.mutex.Unlock()

	return entry.Data, true
}

// Cleanup removes expired cache entries
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

// GetSize returns the number of entries in the cache
func (c *LRUCache) GetSize() int {
	c.mutex.RLock()
	defer c.mutex.RUnlock()
	return len(c.cache)
}

// removeFromAccessOrder removes a key from the accessOrder list
func (c *LRUCache) removeFromAccessOrder(key string) {
	for i, k := range c.accessOrder {
		if k == key {
			c.accessOrder = append(c.accessOrder[:i], c.accessOrder[i+1:]...)
			break
		}
	}
}

// evictLRU removes the least recently used item
func (c *LRUCache) evictLRU() {
	if len(c.accessOrder) == 0 {
		return
	}

	lruKey := c.accessOrder[0]
	delete(c.cache, lruKey)
	c.accessOrder = c.accessOrder[1:]
}

// DNSCacheWithLRU implements an LRU-based DNS cache
type DNSCacheWithLRU struct {
	cache *LRUCache
}

// NewDNSCacheWithLRU creates an LRU-based DNS cache
func NewDNSCacheWithLRU(capacity int, ttl time.Duration) *DNSCacheWithLRU {
	return &DNSCacheWithLRU{
		cache: NewLRUCache(capacity, ttl),
	}
}

// Store saves the DNS result in the cache
func (c *DNSCacheWithLRU) Store(subdomain string, result DNSResult) {
	c.cache.Set(subdomain, result)
}

// Load retrieves a DNS result from the cache
func (c *DNSCacheWithLRU) Load(subdomain string) (DNSResult, bool) {
	val, ok := c.cache.Get(subdomain)
	if !ok {
		return DNSResult{}, false
	}
	return val.(DNSResult), true
}

// StartCleanup starts automatic cache cleanup
func (c *DNSCacheWithLRU) StartCleanup(interval time.Duration) {
	ticker := time.NewTicker(interval)
	go func() {
		for range ticker.C {
			c.cache.Cleanup()
		}
	}()
}
