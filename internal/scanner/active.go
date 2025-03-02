package scanner

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/fkr00t/subcollector/internal/models"
	"github.com/fkr00t/subcollector/internal/output"
	"github.com/fkr00t/subcollector/internal/utils"
)

// ActiveScanConfig menampung konfigurasi untuk pemindaian aktif
type ActiveScanConfig struct {
	Domain         string
	WordlistPath   string
	Resolvers      []string
	RateLimit      int
	Recursive      bool
	ShowIP         bool
	Depth          int
	Takeover       bool
	Proxy          string
	NumWorkers     int
	StreamResults  bool
	OutputFile     string
	JsonOutputFile string
}

// ExecuteActiveScan menjalankan pemindaian aktif dengan konfigurasi yang diberikan
func ExecuteActiveScan(config ActiveScanConfig) {
	// Menampilkan header scan yang minimalis
	fmt.Printf("\n» Scanning %s\n", config.Domain)

	// Tampilkan flags yang aktif secara minimal tapi informatif
	var activeFlags []string

	if config.Takeover {
		activeFlags = append(activeFlags, "takeover")
	}
	if config.ShowIP {
		activeFlags = append(activeFlags, "show-ip")
	}
	if config.Recursive {
		if config.Depth > 0 {
			activeFlags = append(activeFlags, fmt.Sprintf("recursive(depth:%d)", config.Depth))
		} else {
			activeFlags = append(activeFlags, "recursive")
		}
	}
	if config.Proxy != "" {
		activeFlags = append(activeFlags, "proxy")
	}
	if config.OutputFile != "" {
		activeFlags = append(activeFlags, fmt.Sprintf("output:%s", config.OutputFile))
	}
	if config.JsonOutputFile != "" {
		activeFlags = append(activeFlags, fmt.Sprintf("json:%s", config.JsonOutputFile))
	}
	if config.WordlistPath != "" {
		activeFlags = append(activeFlags, fmt.Sprintf("wordlist:%s", config.WordlistPath))
	}

	// Tampilkan flags yang digunakan jika ada
	if len(activeFlags) > 0 {
		fmt.Printf("  flags: %s\n", strings.Join(activeFlags, ", "))
	}

	fmt.Println()

	// Tentukan ambang batas untuk beralih ke pendekatan streaming
	const streamingThreshold = 10000 // 10k entri

	// Cek ukuran wordlist
	var wordlistSize int
	var err error

	// Dapatkan ukuran wordlist
	if config.WordlistPath == "" {
		wordlistSize = 114441
	} else {
		wordlistSize, err = utils.CountLinesInFile(config.WordlistPath)
		if err != nil {
			wordlistSize = 0
		}
	}

	// Pilih metode pemindaian berdasarkan ukuran
	if wordlistSize > streamingThreshold {
		// Tambahkan result processor
		streamingConfig := StreamingActiveScanConfig{
			Domain:       config.Domain,
			WordlistPath: config.WordlistPath,
			Resolvers:    config.Resolvers,
			BackoffConfig: BackoffConfig{
				Enabled:       true,
				BaseDelay:     time.Duration(config.RateLimit) * time.Millisecond,
				MaxDelay:      10 * time.Second,
				Factor:        2.0,
				Jitter:        0.3,
				FailThreshold: 3,
			},
			Recursive:  config.Recursive,
			ShowIP:     config.ShowIP,
			Depth:      config.Depth,
			Takeover:   config.Takeover,
			Proxy:      config.Proxy,
			NumWorkers: config.NumWorkers,
		}

		streamingConfig.ResultProcessor = func(result models.SubdomainResult) {
			output.DisplayResult(result, config.ShowIP)
		}

		// Jalankan pemindaian streaming
		results := streamingActiveScan(streamingConfig)

		// Rangkuman singkat
		fmt.Printf("\n» Found %d subdomains\n", len(results))

		// Simpan hasil jika diminta
		if !config.StreamResults && (config.OutputFile != "" || config.JsonOutputFile != "") {
			output.SaveResults(config.OutputFile, config.JsonOutputFile, config.Domain, results)
			fmt.Printf("» Results saved\n")
		}
	} else {
		// Section untuk subdomain
		results := activeScan(config)

		if results == nil {
			fmt.Println("× Scan failed")
			return
		}

		// Rangkuman singkat
		fmt.Printf("\n» Found %d subdomains\n", len(results))

		// Simpan hasil jika diminta
		if !config.StreamResults && (config.OutputFile != "" || config.JsonOutputFile != "") {
			output.SaveResults(config.OutputFile, config.JsonOutputFile, config.Domain, results)
			fmt.Printf("» Results saved\n")
		}
	}
}

// Fungsi helper untuk menyimpan hasil dari pemindaian streaming
func streamingActiveScan(config StreamingActiveScanConfig) []models.SubdomainResult {
	// Ini adalah wrapper untuk fungsi StreamingActiveScan dari memory_efficient.go
	var collectedResults []models.SubdomainResult
	var resultsMutex sync.Mutex

	// Buat processor yang menyimpan hasil
	originalProcessor := config.ResultProcessor
	config.ResultProcessor = func(result models.SubdomainResult) {
		// Panggil processor asli jika ada
		if originalProcessor != nil {
			originalProcessor(result)
		}

		// Tambahkan ke hasil yang dikumpulkan
		resultsMutex.Lock()
		collectedResults = append(collectedResults, result)
		resultsMutex.Unlock()
	}

	// Simulasi dengan menggunakan active scan
	tempConfig := ActiveScanConfig{
		Domain:        config.Domain,
		WordlistPath:  config.WordlistPath,
		Resolvers:     config.Resolvers,
		RateLimit:     int(config.BackoffConfig.BaseDelay / time.Millisecond),
		Recursive:     config.Recursive,
		ShowIP:        config.ShowIP,
		Depth:         config.Depth,
		Takeover:      config.Takeover,
		Proxy:         config.Proxy,
		NumWorkers:    config.NumWorkers,
		StreamResults: false,
	}

	// Memanggil fungsi activeScan untuk sementara sampai StreamingActiveScan diimplementasikan
	temporaryResults := activeScan(tempConfig)

	// Simulasi memanggil processor hasil
	for _, result := range temporaryResults {
		if config.ResultProcessor != nil {
			config.ResultProcessor(result)
		}
	}

	return collectedResults
}

// activeScan melakukan enumerasi subdomain aktif menggunakan wordlist
// Mencoba menemukan subdomain dengan menambahkan kata-kata dari wordlist ke domain
func activeScan(config ActiveScanConfig) []models.SubdomainResult {
	var wordlist []string
	var err error

	// Load atau download wordlist
	if config.WordlistPath == "" {
		defaultWordlistURL := "https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Discovery/DNS/subdomains-top1million-110000.txt"
		fmt.Println("» Downloading wordlist...")
		wordlist, err = utils.FetchWordlistFromURL(defaultWordlistURL)
		if err != nil {
			fmt.Println("× Failed to fetch wordlist")
			return nil
		}
	} else {
		wordlist, err = utils.LoadWordlist(config.WordlistPath)
		if err != nil {
			fmt.Println("× Wordlist file not found")
			return nil
		}
	}

	// Proses resolver
	var finalResolvers []string
	finalResolvers = processResolvers(config.Resolvers)

	// Siapkan HTTP client untuk pemeriksaan takeover
	client := setupHTTPClient(config.Takeover, config.Proxy)

	var results []models.SubdomainResult
	cache := models.NewDNSCache()
	level := 1
	toScan := []string{config.Domain}

	// Channel untuk streaming hasil jika diaktifkan
	var streamChan chan models.SubdomainResult
	if config.StreamResults {
		streamChan = setupStreamChannel(config.ShowIP)
	} else {
		streamChan = nil
	}

	// Untuk tiap level rekursif
	for len(toScan) > 0 && (config.Depth == -1 || level <= config.Depth) {
		if level > 1 || config.Recursive {
			fmt.Printf("\n» Level %d: %d domains\n", level, len(toScan))
		}

		levelResults := scanLevel(
			toScan,
			wordlist,
			finalResolvers,
			cache,
			client,
			config,
			streamChan,
		)

		// Proses hasil level ini untuk level berikutnya jika rekursif
		results = append(results, levelResults...)
		if config.Recursive && (config.Depth == -1 || level < config.Depth) {
			toScan = []string{}
			for _, res := range levelResults {
				toScan = append(toScan, res.Subdomain)
			}
			level++
		} else {
			toScan = []string{}
		}
	}

	if streamChan != nil && config.Recursive {
		close(streamChan)
	}

	return results
}

// processResolvers memproses resolver yang diberikan
func processResolvers(resolvers []string) []string {
	var finalResolvers []string
	if len(resolvers) == 1 && utils.IsResolverFile(resolvers[0]) {
		fileResolvers, err := utils.LoadResolvers(resolvers[0])
		if err != nil {
			return nil
		}
		finalResolvers = fileResolvers
		fmt.Printf("» Using %d resolvers from file\n", len(finalResolvers))
	} else if len(resolvers) > 0 {
		finalResolvers = resolvers
		fmt.Printf("» Using %d custom resolvers\n", len(finalResolvers))
	}
	return finalResolvers
}

// setupHTTPClient menyiapkan HTTP client untuk pemeriksaan takeover
func setupHTTPClient(takeover bool, proxy string) *http.Client {
	if !takeover {
		return nil
	}

	if proxy != "" {
		proxyURL, err := url.Parse(proxy)
		if err != nil {
			return nil
		}
		transport := &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		}
		return &http.Client{Transport: transport, Timeout: 5 * time.Second}
	}

	return &http.Client{Timeout: 5 * time.Second}
}

// setupStreamChannel menyiapkan channel untuk streaming hasil
func setupStreamChannel(showIP bool) chan models.SubdomainResult {
	streamChan := make(chan models.SubdomainResult, 100)

	// Set up goroutine untuk memproses hasil streaming
	go func() {
		for result := range streamChan {
			output.DisplayResult(result, showIP)
		}
	}()

	return streamChan
}

// scanLevel melakukan pemindaian untuk satu level rekursi
func scanLevel(
	toScan []string,
	wordlist []string,
	resolvers []string,
	cache *models.DNSCache,
	client *http.Client,
	config ActiveScanConfig,
	streamChan chan models.SubdomainResult,
) []models.SubdomainResult {
	var levelResults []models.SubdomainResult
	var wg sync.WaitGroup
	subdomainChan := make(chan string, 100)
	resultChan := make(chan models.SubdomainResult, 100)

	// Tampilkan total task yang akan dikerjakan
	totalTasks := len(toScan) * len(wordlist)
	fmt.Printf("» Checking %d subdomains\n", totalTasks)

	// Buat progress bar
	bar := utils.CreateProgressBar(totalTasks)

	// Setup result writer untuk tampilan real-time
	var resultWriter *output.ResultWriter
	resultWriter = output.NewResultWriter(bar, config.ShowIP)

	// Mulai progress bar
	bar.Start()

	// Buat worker pool
	for i := 0; i < config.NumWorkers; i++ {
		wg.Add(1)
		go Worker(
			subdomainChan,
			resultChan,
			resolvers,
			cache,
			client,
			bar,
			resultWriter,
			&wg,
			config.ShowIP,
			config.RateLimit,
			streamChan,
		)
	}

	// Feed subdomain ke worker
	go func() {
		for _, target := range toScan {
			for _, word := range wordlist {
				subdomain := word + "." + target
				subdomainChan <- subdomain
			}
		}
		close(subdomainChan)
	}()

	// Kumpulkan hasil
	go func() {
		wg.Wait()
		close(resultChan)
		if streamChan != nil && !config.Recursive {
			close(streamChan)
		}
	}()

	// Proses dan simpan hasil untuk level ini
	for result := range resultChan {
		levelResults = append(levelResults, result)
	}

	bar.Finish()

	return levelResults
}
