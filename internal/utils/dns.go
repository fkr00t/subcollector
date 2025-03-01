package utils

import (
	"context"
	"net"
	"strings"
)

// LookupWithResolver melakukan pencarian DNS menggunakan resolver tertentu
// Ini memungkinkan kontrol lebih atas proses resolusi DNS
// Mengembalikan slice alamat IP dan error yang ditemui
func LookupWithResolver(domain string, resolver string) ([]string, error) {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{}
			return d.DialContext(ctx, "udp", resolver+":53")
		},
	}
	return r.LookupHost(context.Background(), domain)
}

// DefaultLookup melakukan pencarian DNS menggunakan resolver default sistem
func DefaultLookup(domain string) ([]string, error) {
	return net.LookupHost(domain)
}

// CleanDomain menghapus prefiks umum dan whitespace dari domain
// Ini memastikan format domain yang konsisten untuk pemrosesan
func CleanDomain(domain string) string {
	domain = strings.TrimSpace(domain)
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimPrefix(domain, "www.")
	return domain
}

// IsResolverFile memeriksa apakah string resolver adalah file
func IsResolverFile(resolver string) bool {
	return strings.Contains(resolver, ".") && !strings.Contains(resolver, ",")
}
