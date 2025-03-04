package models

// SubdomainResult represents the result of discovering a subdomain with its associated data
type SubdomainResult struct {
	Subdomain string   `json:"subdomain"`          // The discovered subdomain
	IPs       []string `json:"ips,omitempty"`      // Associated IP addresses for the subdomain
	Takeover  string   `json:"takeover,omitempty"` // Potential takeover vulnerability
}

// OutputJSON represents the complete output structure for JSON serialization
type OutputJSON struct {
	Domain     string            `json:"domain"`     // The main scanned domain
	Subdomains []SubdomainResult `json:"subdomains"` // List of discovered subdomains
}
