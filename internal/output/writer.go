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

// ResultWriter manages real-time output of results while maintaining the progress bar
type ResultWriter struct {
	bar           *pb.ProgressBar
	mutex         *sync.Mutex
	results       []models.SubdomainResult
	showIP        bool
	foundTakeover bool // Tracks if a takeover is detected
}

// NewResultWriter creates a new instance of ResultWriter
func NewResultWriter(bar *pb.ProgressBar, showIP bool) *ResultWriter {
	return &ResultWriter{
		bar:           bar,
		mutex:         &sync.Mutex{},
		results:       []models.SubdomainResult{},
		showIP:        showIP,
		foundTakeover: false,
	}
}

// WriteResult writes a new result while keeping the progress bar intact
func (rw *ResultWriter) WriteResult(result models.SubdomainResult) {
	rw.mutex.Lock()
	defer rw.mutex.Unlock()

	// Store result
	rw.results = append(rw.results, result)

	// Update takeover flag if detected
	if result.Takeover != "" {
		rw.foundTakeover = true
	}

	// Save the current progress bar status
	barString := rw.bar.String()

	// Clear the line
	fmt.Print("\r\033[K")

	// Print result - minimalist style
	DisplayResult(result, rw.showIP)

	// Restore the progress bar on the next line
	fmt.Print(barString)
}

// GetResults returns all stored results
func (rw *ResultWriter) GetResults() []models.SubdomainResult {
	rw.mutex.Lock()
	defer rw.mutex.Unlock()
	return rw.results
}

// DisplayResult formats and prints a single subdomain result
func DisplayResult(result models.SubdomainResult, showIP bool) {
	subdomain := cyan(result.Subdomain)

	if result.Takeover != "" {
		// Prioritize displaying takeover alerts with a clear flag
		if showIP && len(result.IPs) > 0 {
			fmt.Printf(" !  %s (%s) | %s\n", subdomain, result.IPs[0], red("Possible Takeover: "+result.Takeover))
		} else {
			fmt.Printf(" !  %s | %s\n", subdomain, red("Possible Takeover: "+result.Takeover))
		}
	} else {
		// Normal display for subdomains without takeover warnings
		if showIP && len(result.IPs) > 0 {
			fmt.Printf(" +  %s → %s\n", subdomain, result.IPs[0])
		} else {
			fmt.Printf(" +  %s\n", subdomain)
		}
	}
}
