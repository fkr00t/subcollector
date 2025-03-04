package utils

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// ExtractRootDomain extracts the root domain from a subdomain
// Used for rate limiting purposes
func ExtractRootDomain(subdomain string) string {
	parts := strings.Split(subdomain, ".")

	// If it has only 1 part, return as-is
	if len(parts) <= 1 {
		return subdomain
	}

	// If it has 2 parts, return the whole thing
	if len(parts) == 2 {
		return subdomain
	}

	// For longer subdomains, take the last 2 parts
	// example: sub.example.com -> example.com
	return strings.Join(parts[len(parts)-2:], ".")
}

// ParseCIDR extracts and validates a CIDR range
func ParseCIDR(cidr string) (string, int, error) {
	parts := strings.Split(cidr, "/")
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("invalid CIDR format: %s", cidr)
	}

	ip := parts[0]
	mask, err := strconv.Atoi(parts[1])
	if err != nil {
		return "", 0, fmt.Errorf("invalid CIDR mask: %s", parts[1])
	}

	if mask < 0 || mask > 32 {
		return "", 0, fmt.Errorf("CIDR mask must be between 0 and 32, found: %d", mask)
	}

	// Validate IP
	if net.ParseIP(ip) == nil {
		return "", 0, fmt.Errorf("invalid IP address: %s", ip)
	}

	return ip, mask, nil
}

// IsSubdomainOf checks if a domain is a subdomain of parentDomain
func IsSubdomainOf(domain, parentDomain string) bool {
	domain = strings.TrimSuffix(domain, ".")
	parentDomain = strings.TrimSuffix(parentDomain, ".")

	if domain == parentDomain {
		return false // Same domain is not a subdomain
	}

	return strings.HasSuffix(domain, "."+parentDomain)
}

// CountSubdomainLevels counts the number of levels in a subdomain
func CountSubdomainLevels(domain string) int {
	return len(strings.Split(domain, ".")) - 1
}

// IsValidDomain checks if a string is a valid domain
func IsValidDomain(domain string) bool {
	domain = CleanDomain(domain)

	// Domain cannot be empty
	if domain == "" {
		return false
	}

	// Domain cannot contain illegal characters
	invalidChars := []string{" ", "!", "@", "#", "$", "%", "^", "&", "*", "(", ")", "+", "=", "{", "}", "[", "]", ":", ";", "'", "\"", "<", ">", ",", "?", "/", "\\", "|"}
	for _, char := range invalidChars {
		if strings.Contains(domain, char) {
			return false
		}
	}

	// Domain must have at least one dot
	if !strings.Contains(domain, ".") {
		return false
	}

	// Domain must end with a valid TLD
	// This is a simple check, you might want to use a library like tldextract
	parts := strings.Split(domain, ".")
	tld := parts[len(parts)-1]

	// TLD must be at least 2 characters
	if len(tld) < 2 {
		return false
	}

	// TLD must be all letters (simple check)
	for _, c := range tld {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
			return false
		}
	}

	return true
}
