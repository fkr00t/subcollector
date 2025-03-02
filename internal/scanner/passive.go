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

// PassiveScanConfig menampung konfigurasi untuk pemindaian pasif
type PassiveScanConfig struct {
	Domain         string
	ShowIP         bool
	StreamResults  bool
	OutputFile     string
	JsonOutputFile string
}

// ExecutePassiveScan menjalankan pemindaian pasif dengan konfigurasi yang diberikan
func ExecutePassiveScan(config PassiveScanConfig) {
	fmt.Printf("[INF] Memulai pemindaian pasif untuk %s...\n\n", config.Domain)
	//utils.GlobalLogger.Info("Memulai pemindaian pasif untuk %s...", config.Domain)

	// Siapkan channel untuk streaming hasil jika diaktifkan
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
		fmt.Printf("[ERR] Pemindaian pasif gagal untuk %s: %v\n", config.Domain, err)
		//utils.GlobalLogger.Error("Pemindaian pasif gagal untuk %s: %v", config.Domain, err)
		return
	}

	// Stream hasil jika diaktifkan
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
			fmt.Printf("[INF] Hasil disimpan ke %s\n", outputFile)
		}
	} else {
		// Tampilkan hasil
		for _, result := range results {
			output.DisplayResult(result, config.ShowIP)
		}

		// Simpan hasil jika diminta
		if (config.OutputFile != "" || config.JsonOutputFile != "") && !config.StreamResults {
			output.SaveResults(config.OutputFile, config.JsonOutputFile, config.Domain, results)
		}
	}
}

// passiveScan melakukan enumerasi subdomain pasif menggunakan subfinder
// Menggunakan sumber eksternal untuk menemukan subdomain tanpa interaksi langsung dengan target
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
