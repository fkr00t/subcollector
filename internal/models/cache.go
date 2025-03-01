package models

import "sync"

// DNSResult merepresentasikan hasil dari pencarian DNS, digunakan dalam cache
type DNSResult struct {
	Found bool     // Apakah subdomain ada
	IPs   []string // Alamat IP yang terkait dengan subdomain jika ditemukan
}

// DNSCache menyediakan cache thread-safe untuk hasil DNS
type DNSCache struct {
	cache *sync.Map
}

// NewDNSCache membuat instance baru dari DNSCache
func NewDNSCache() *DNSCache {
	return &DNSCache{
		cache: &sync.Map{},
	}
}

// Store menyimpan hasil DNS ke dalam cache
func (c *DNSCache) Store(subdomain string, result DNSResult) {
	c.cache.Store(subdomain, result)
}

// Load mengambil hasil DNS dari cache
func (c *DNSCache) Load(subdomain string) (DNSResult, bool) {
	val, ok := c.cache.Load(subdomain)
	if !ok {
		return DNSResult{}, false
	}
	return val.(DNSResult), true
}
