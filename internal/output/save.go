package output

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/fkr00t/subcollector/internal/models"
)

// SaveResults saves scan results to a file
// Supports text and JSON formats
// Returns an error if an issue occurs
func SaveResults(output, jsonOutput, domain string, results []models.SubdomainResult) error {
	outputFile := output
	if jsonOutput != "" {
		outputFile = jsonOutput
		if outputFile == "" {
			outputFile = "output.json"
		}
	}

	file, err := os.Create(outputFile)
	if err != nil {
		fmt.Println("[ERR] Failed to create output file!")
		return err
	}
	defer file.Close()

	if jsonOutput != "" {
		outputData := models.OutputJSON{
			Domain:     domain,
			Subdomains: results,
		}
		jsonData, err := json.MarshalIndent(outputData, "", "    ")
		if err != nil {
			fmt.Println("[ERR] Failed to generate JSON output!")
			return err
		}
		_, err = file.Write(jsonData)
		if err != nil {
			return err
		}
		fmt.Printf("[INF] Results saved to %s (JSON format)\n", outputFile)
	} else {
		for _, result := range results {
			_, err := file.WriteString(fmt.Sprintf("%s\n", result.Subdomain))
			if err != nil {
				return err
			}
		}
		fmt.Printf("[INF] Results saved to %s (text format)\n", outputFile)
	}

	return nil
}

// BatchSaveResultsJSON saves results in batches to avoid storing all results in memory
// This function processes the result channel and writes directly to a JSON file
func BatchSaveResultsJSON(outputFile, domain string, resultsChan <-chan models.SubdomainResult, doneChan chan<- bool) {
	file, err := os.Create(outputFile)
	if err != nil {
		fmt.Println("[ERR] Failed to create output file!")
		doneChan <- false
		return
	}
	defer file.Close()

	// Initialize JSON array
	file.WriteString(fmt.Sprintf("{\n  \"domain\": \"%s\",\n  \"subdomains\": [\n", domain))

	first := true
	for result := range resultsChan {
		jsonData, err := json.Marshal(result)
		if err != nil {
			continue
		}

		if !first {
			file.WriteString(",\n")
		} else {
			first = false
		}

		file.WriteString("    " + string(jsonData))
	}

	// Close JSON array and object
	file.WriteString("\n  ]\n}")

	doneChan <- true
}

// BatchSaveResultsText saves results in batches to avoid storing all results in memory
// This function processes the result channel and writes directly to a text file
func BatchSaveResultsText(outputFile string, resultsChan <-chan models.SubdomainResult, doneChan chan<- bool) {
	file, err := os.Create(outputFile)
	if err != nil {
		fmt.Println("[ERR] Failed to create output file!")
		doneChan <- false
		return
	}
	defer file.Close()

	// Simple text format
	for result := range resultsChan {
		file.WriteString(fmt.Sprintf("%s\n", result.Subdomain))
	}

	doneChan <- true
}
