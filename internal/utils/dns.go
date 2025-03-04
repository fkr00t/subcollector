package utils

import (
	"context"
	"net"
	"strings"
)

// LookupWithResolver performs DNS lookup using a specific resolver
// This allows more control over the DNS resolution process
// Returns a slice of IP addresses and any errors encountered
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

// DefaultLookup performs DNS lookup using the system's default resolver
func DefaultLookup(domain string) ([]string, error) {
	return net.LookupHost(domain)
}

// CleanDomain removes common prefixes and whitespace from a domain
// This ensures consistent domain format for processing
func CleanDomain(domain string) string {
	domain = strings.TrimSpace(domain)
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimPrefix(domain, "www.")
	return domain
}

// IsResolverFile checks if a resolver string is a file
func IsResolverFile(resolver string) bool {
	return strings.Contains(resolver, ".") && !strings.Contains(resolver, ",")
}
