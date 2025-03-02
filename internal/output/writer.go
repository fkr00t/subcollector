package output

import (
	"fmt"
	"github.com/cheggaaa/pb/v3"
	"github.com/fatih/color"
	"github.com/fkr00t/subcollector/internal/models"
	"sync"
)

var (
	green  = color.New(color.FgGreen).SprintFunc()
	yellow = color.New(color.FgYellow).SprintFunc()
	cyan   = color.New(color.FgCyan).SprintFunc()
	red    = color.New(color.FgRed).SprintFunc()
)

// ResultWriter mengelola output real-time dari hasil sambil menjaga progress bar tetap utuh
type ResultWriter struct {
	bar           *pb.ProgressBar
	mutex         *sync.Mutex
	results       []models.SubdomainResult
	showIP        bool
	foundTakeover bool // Untuk melacak jika ada takeover yang ditemukan
}

// NewResultWriter membuat instance baru ResultWriter
func NewResultWriter(bar *pb.ProgressBar, showIP bool) *ResultWriter {
	return &ResultWriter{
		bar:           bar,
		mutex:         &sync.Mutex{},
		results:       []models.SubdomainResult{},
		showIP:        showIP,
		foundTakeover: false,
	}
}

// WriteResult menulis hasil baru sambil mempertahankan progress bar
func (rw *ResultWriter) WriteResult(result models.SubdomainResult) {
	rw.mutex.Lock()
	defer rw.mutex.Unlock()

	// Simpan hasil
	rw.results = append(rw.results, result)

	// Update flag takeover jika ditemukan
	if result.Takeover != "" {
		rw.foundTakeover = true
	}

	// Simpan status progress bar saat ini
	barString := rw.bar.String()

	// Bersihkan baris
	fmt.Print("\r\033[K")

	// Print hasil - minimalist style
	DisplayResult(result, rw.showIP)

	// Kembalikan progress bar pada baris berikutnya
	fmt.Print(barString)
}

// GetResults mengembalikan semua hasil yang disimpan
func (rw *ResultWriter) GetResults() []models.SubdomainResult {
	rw.mutex.Lock()
	defer rw.mutex.Unlock()
	return rw.results
}

func DisplayResult(result models.SubdomainResult, showIP bool) {
	subdomain := cyan(result.Subdomain)

	if result.Takeover != "" {
		// Prioritaskan tampilan takeover dengan flag jelas
		if showIP && len(result.IPs) > 0 {
			fmt.Printf(" !  %s (%s) | %s\n", subdomain, result.IPs[0], red("Possible Takeover: "+result.Takeover))
		} else {
			fmt.Printf(" !  %s | %s\n", subdomain, red("Possible Takeover: "+result.Takeover))
		}
	} else {
		// Display normal untuk subdomain tanpa takeover
		if showIP && len(result.IPs) > 0 {
			fmt.Printf(" +  %s → %s\n", subdomain, result.IPs[0])
		} else {
			fmt.Printf(" +  %s\n", subdomain)
		}
	}
}
