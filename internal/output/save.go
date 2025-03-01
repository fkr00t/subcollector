package output

import (
	"encoding/json"
	"fmt"
	"os"

	"subcollector/internal/models"
)

// SaveResults menyimpan hasil pemindaian ke file
// Mendukung format teks dan JSON
// Mengembalikan error jika ada masalah
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
		fmt.Println("[ERR] Gagal membuat file output!")
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
			fmt.Println("[ERR] Gagal membuat output JSON!")
			return err
		}
		_, err = file.Write(jsonData)
		if err != nil {
			return err
		}
		fmt.Printf("[INF] Hasil disimpan ke %s (format JSON)\n", outputFile)
	} else {
		for _, result := range results {
			_, err := file.WriteString(fmt.Sprintf("%s\n", result.Subdomain))
			if err != nil {
				return err
			}
		}
		fmt.Printf("[INF] Hasil disimpan ke %s (format teks)\n", outputFile)
	}

	return nil
}

// BatchSaveResultsJSON menyimpan hasil dalam batch untuk menghindari menyimpan semua hasil di memori
// Fungsi ini memproses channel hasil dan menulisnya langsung ke file JSON
func BatchSaveResultsJSON(outputFile, domain string, resultsChan <-chan models.SubdomainResult, doneChan chan<- bool) {
	file, err := os.Create(outputFile)
	if err != nil {
		fmt.Println("[ERR] Gagal membuat file output!")
		doneChan <- false
		return
	}
	defer file.Close()

	// Inisialisasi array JSON
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

	// Tutup array JSON dan objek
	file.WriteString("\n  ]\n}")

	doneChan <- true
}

// BatchSaveResultsText menyimpan hasil dalam batch untuk menghindari menyimpan semua hasil di memori
// Fungsi ini memproses channel hasil dan menulisnya langsung ke file teks
func BatchSaveResultsText(outputFile string, resultsChan <-chan models.SubdomainResult, doneChan chan<- bool) {
	file, err := os.Create(outputFile)
	if err != nil {
		fmt.Println("[ERR] Gagal membuat file output!")
		doneChan <- false
		return
	}
	defer file.Close()

	// Format teks sederhana
	for result := range resultsChan {
		file.WriteString(fmt.Sprintf("%s\n", result.Subdomain))
	}

	doneChan <- true
}
