package scanner

import (
	"fmt"
	"io"
	"net"

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
	fmt.Printf("[INF] Starting passive scan for %s...\n\n", config.Domain)
	//utils.GlobalLogger.Info("Starting passive scan for %s...", config.Domain)

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
		fmt.Printf("[ERR] Passive scan failed for %s: %v\n", config.Domain, err)
		//utils.GlobalLogger.Error("Passive scan failed for %s: %v", config.Domain, err)
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
			fmt.Printf("[INF] Results saved to %s\n", outputFile)
		}
	} else {
		// Display results
		for _, result := range results {
			output.DisplayResult(result, config.ShowIP)
		}

		// Save results if requested
		if (config.OutputFile != "" || config.JsonOutputFile != "") && !config.StreamResults {
			output.SaveResults(config.OutputFile, config.JsonOutputFile, config.Domain, results)
		}
	}
}

// passiveScan performs passive subdomain enumeration using subfinder
// Uses external sources to find subdomains without direct interaction with the target
func passiveScan(domain string, showIP bool) ([]models.SubdomainResult, error) {
	stopChan := make(chan bool)
	go utils.ShowLoading(stopChan)

	options := &runner.Options{
		Threads:            10,
		Timeout:            30,
		MaxEnumerationTime: 10,
		Silent:             true,
	}

	runnerInstance, err := runner.NewRunner(options)
	if err != nil {
		stopChan <- true
		return nil, err
	}

	results, err := runnerInstance.EnumerateSingleDomain(domain, []io.Writer{io.Discard})
	if err != nil {
		stopChan <- true
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

	stopChan <- true
	return subdomains, nil
}
