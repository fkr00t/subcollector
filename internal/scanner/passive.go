package scanner

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/fkr00t/subcollector/internal/models"
	"github.com/fkr00t/subcollector/internal/output"
	"github.com/fkr00t/subcollector/internal/utils"
	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
)

// PassiveScanConfig holds configuration for passive scanning
type PassiveScanConfig struct {
	Domain         string
	ShowIP         bool
	StreamResults  bool
	OutputFile     string
	JsonOutputFile string
}

// ExecutePassiveScan runs a passive scan with the provided configuration
func ExecutePassiveScan(config PassiveScanConfig) {
	// Display a minimalist scan header (mirip dengan active scanning)
	fmt.Printf("\n» Scanning %s (passive mode)\n", config.Domain)

	// Display passive flags in a minimal but informative way
	var passiveFlags []string

	if config.ShowIP {
		passiveFlags = append(passiveFlags, "show-ip")
	}
	if config.StreamResults {
		passiveFlags = append(passiveFlags, "stream")
	}
	if config.OutputFile != "" {
		passiveFlags = append(passiveFlags, fmt.Sprintf("output:%s", config.OutputFile))
	}
	if config.JsonOutputFile != "" {
		passiveFlags = append(passiveFlags, fmt.Sprintf("json:%s", config.JsonOutputFile))
	}

	// Display the flags used, if any
	if len(passiveFlags) > 0 {
		fmt.Printf("  flags: %s\n", strings.Join(passiveFlags, ", "))
	}

	fmt.Println()

	// Set up channel for streaming results if enabled
	var resultsChan chan models.SubdomainResult
	var doneChan chan bool

	if config.StreamResults && (config.OutputFile != "" || config.JsonOutputFile != "") {
		resultsChan = make(chan models.SubdomainResult, 100)
		doneChan = make(chan bool)

		outputFile := config.OutputFile
		if config.JsonOutputFile != "" {
			outputFile = config.JsonOutputFile
			go output.BatchSaveResultsJSON(outputFile, config.Domain, resultsChan, doneChan)
		} else {
			go output.BatchSaveResultsText(outputFile, resultsChan, doneChan)
		}
	}

	results, err := passiveScan(config.Domain, config.ShowIP)
	if err != nil {
		fmt.Printf("× Passive scan failed for %s: %v\n", config.Domain, err)
		return
	}

	// Stream results if enabled
	if config.StreamResults && resultsChan != nil {
		for _, result := range results {
			resultsChan <- result
		}
		close(resultsChan)
		success := <-doneChan
		if success {
			outputFile := config.OutputFile
			if config.JsonOutputFile != "" {
				outputFile = config.JsonOutputFile
			}
			fmt.Printf("» Results saved to %s\n", outputFile)
		}
	} else {
		// Display results
		for _, result := range results {
			output.DisplayResult(result, config.ShowIP)
		}

		// Save results if requested
		if (config.OutputFile != "" || config.JsonOutputFile != "") && !config.StreamResults {
			output.SaveResults(config.OutputFile, config.JsonOutputFile, config.Domain, results)
			fmt.Printf("» Results saved\n")
		}
	}

	// Brief summary at the end, similar to active scanning
	fmt.Printf("\n» Found %d subdomains\n", len(results))
}

// passiveScan performs passive subdomain enumeration using subfinder
// Uses external sources to find subdomains without direct interaction with the target
func passiveScan(domain string, showIP bool) ([]models.SubdomainResult, error) {
	fmt.Printf("» Starting passive scan for %s\n", domain)
	fmt.Printf("» Querying passive sources...\n")

	// Create a progress bar for consistent UI with active scanning
	bar := utils.CreateProgressBar(100) // Menggunakan 100 sebagai placeholder karena kita tidak tahu pasti berapa banyak hasil
	bar.Start()

	// Setup countdown timer for consistent feedback
	updateTicker := time.NewTicker(500 * time.Millisecond)
	defer updateTicker.Stop()

	// Create a context that we can cancel
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle interrupt signal for clean exit
	interruptChan := make(chan os.Signal, 1)
	signal.Notify(interruptChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		select {
		case <-interruptChan:
			cancel() // Cancel context to stop progress updater
			bar.Finish()
			fmt.Println("\nBye!")
			os.Exit(0)
		case <-ctx.Done():
			return
		}
	}()

	// Progress updater goroutine
	go func() {
		progress := 0
		for {
			select {
			case <-ctx.Done():
				return
			case <-updateTicker.C:
				progress += 2
				if progress > 95 {
					progress = 95 // Cap at 95% until we're done
				}
				bar.SetCurrent(int64(progress))
			}
		}
	}()

	options := &runner.Options{
		Threads:            10,
		Timeout:            30,
		MaxEnumerationTime: 10,
		Silent:             true,
	}

	runnerInstance, err := runner.NewRunner(options)
	if err != nil {
		bar.Finish()
		signal.Stop(interruptChan)
		return nil, err
	}

	results, err := runnerInstance.EnumerateSingleDomain(domain, []io.Writer{io.Discard})
	if err != nil {
		bar.Finish()
		signal.Stop(interruptChan)
		return nil, err
	}

	var subdomains []models.SubdomainResult
	for result := range results {
		subdomainResult := models.SubdomainResult{Subdomain: result}

		if showIP {
			ips, err := net.LookupHost(result)
			if err == nil {
				subdomainResult.IPs = ips
			}
		}

		subdomains = append(subdomains, subdomainResult)
	}

	// Clean up signal handling
	signal.Stop(interruptChan)

	// Completed!
	bar.SetCurrent(100)
	bar.Finish()

	fmt.Printf("» Found %d subdomains via passive sources\n", len(subdomains))

	return subdomains, nil
}
