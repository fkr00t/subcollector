package models

// SubdomainResult merepresentasikan hasil penemuan satu subdomain dengan data terkait
type SubdomainResult struct {
	Subdomain string   `json:"subdomain"`          // Subdomain yang ditemukan
	IPs       []string `json:"ips,omitempty"`      // Alamat IP yang terkait dengan subdomain
	Takeover  string   `json:"takeover,omitempty"` // Potensi layanan yang bisa diambil alih
}

// OutputJSON merepresentasikan struktur output lengkap untuk serialisasi JSON
type OutputJSON struct {
	Domain     string            `json:"domain"`     // Domain utama yang dipindai
	Subdomains []SubdomainResult `json:"subdomains"` // Daftar subdomain yang ditemukan
}
