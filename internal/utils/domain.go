package utils

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// ExtractRootDomain mengekstrak domain root dari subdomain
// Digunakan untuk tujuan rate limiting
func ExtractRootDomain(subdomain string) string {
	parts := strings.Split(subdomain, ".")

	// Jika hanya memiliki 1 bagian, kembalikan as-is
	if len(parts) <= 1 {
		return subdomain
	}

	// Jika memiliki 2 bagian, kembalikan seluruhnya
	if len(parts) == 2 {
		return subdomain
	}

	// Untuk subdomain yang lebih panjang, ambil 2 bagian terakhir
	// contoh: sub.example.com -> example.com
	return strings.Join(parts[len(parts)-2:], ".")
}

// ParseCIDR mengekstrak dan memvalidasi rentang CIDR
func ParseCIDR(cidr string) (string, int, error) {
	parts := strings.Split(cidr, "/")
	if len(parts) != 2 {
		return "", 0, fmt.Errorf("format CIDR tidak valid: %s", cidr)
	}

	ip := parts[0]
	mask, err := strconv.Atoi(parts[1])
	if err != nil {
		return "", 0, fmt.Errorf("mask CIDR tidak valid: %s", parts[1])
	}

	if mask < 0 || mask > 32 {
		return "", 0, fmt.Errorf("mask CIDR harus antara 0 dan 32, ditemukan: %d", mask)
	}

	// Validasi IP
	if net.ParseIP(ip) == nil {
		return "", 0, fmt.Errorf("alamat IP tidak valid: %s", ip)
	}

	return ip, mask, nil
}

// IsSubdomainOf memeriksa apakah domain adalah subdomain dari parentDomain
func IsSubdomainOf(domain, parentDomain string) bool {
	domain = strings.TrimSuffix(domain, ".")
	parentDomain = strings.TrimSuffix(parentDomain, ".")

	if domain == parentDomain {
		return false // Domain sama bukan subdomain
	}

	return strings.HasSuffix(domain, "."+parentDomain)
}

// CountSubdomainLevels menghitung jumlah level dalam subdomain
func CountSubdomainLevels(domain string) int {
	return len(strings.Split(domain, ".")) - 1
}

// IsValidDomain memeriksa apakah string adalah domain yang valid
func IsValidDomain(domain string) bool {
	domain = CleanDomain(domain)

	// Domain tidak boleh kosong
	if domain == "" {
		return false
	}

	// Domain tidak boleh mengandung karakter ilegal
	invalidChars := []string{" ", "!", "@", "#", "$", "%", "^", "&", "*", "(", ")", "+", "=", "{", "}", "[", "]", ":", ";", "'", "\"", "<", ">", ",", "?", "/", "\\", "|"}
	for _, char := range invalidChars {
		if strings.Contains(domain, char) {
			return false
		}
	}

	// Domain harus memiliki setidaknya satu dot
	if !strings.Contains(domain, ".") {
		return false
	}

	// Domain harus diakhiri dengan TLD yang valid
	// Ini adalah pemeriksaan sederhana, Anda mungkin ingin menggunakan library seperti tldextract
	parts := strings.Split(domain, ".")
	tld := parts[len(parts)-1]

	// TLD minimal 2 karakter
	if len(tld) < 2 {
		return false
	}

	// TLD harus semua huruf (pemeriksaan sederhana)
	for _, c := range tld {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
			return false
		}
	}

	return true
}
