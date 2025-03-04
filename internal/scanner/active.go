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

// ActiveScanConfig holds the configuration for active scanning
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

// ExecuteActiveScan runs an active scan with the provided configuration
func ExecuteActiveScan(config ActiveScanConfig) {
	// Display a minimalist scan header
	fmt.Printf("\n» Scanning %s\n", config.Domain)

	// Display active flags in a minimal but informative way
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

	// Display the flags used, if any
	if len(activeFlags) > 0 {
		fmt.Printf("  flags: %s\n", strings.Join(activeFlags, ", "))
	}

	fmt.Println()

	// Define threshold for switching to streaming approach
	const streamingThreshold = 10000 // 10k entries

	// Check wordlist size
	var wordlistSize int
	var err error

	// Get wordlist size
	if config.WordlistPath == "" {
		wordlistSize = 114441
	} else {
		wordlistSize, err = utils.CountLinesInFile(config.WordlistPath)
		if err != nil {
			wordlistSize = 0
		}
	}

	// Choose scanning method based on size
	if wordlistSize > streamingThreshold {
		// Add result processor
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

		// Run streaming scan
		results := streamingActiveScan(streamingConfig)

		// Brief summary
		fmt.Printf("\n» Found %d subdomains\n", len(results))

		// Save results if requested
		if !config.StreamResults && (config.OutputFile != "" || config.JsonOutputFile != "") {
			output.SaveResults(config.OutputFile, config.JsonOutputFile, config.Domain, results)
			fmt.Printf("» Results saved\n")
		}
	} else {
		// Section for subdomains
		results := activeScan(config)

		if results == nil {
			fmt.Println("× Scan failed")
			return
		}

		// Brief summary
		fmt.Printf("\n» Found %d subdomains\n", len(results))

		// Save results if requested
		if !config.StreamResults && (config.OutputFile != "" || config.JsonOutputFile != "") {
			output.SaveResults(config.OutputFile, config.JsonOutputFile, config.Domain, results)
			fmt.Printf("» Results saved\n")
		}
	}
}

// Helper function to save results from streaming scan
func streamingActiveScan(config StreamingActiveScanConfig) []models.SubdomainResult {
	// This is a wrapper for the StreamingActiveScan function from memory_efficient.go
	var collectedResults []models.SubdomainResult
	var resultsMutex sync.Mutex

	// Create a processor that saves the results
	originalProcessor := config.ResultProcessor
	config.ResultProcessor = func(result models.SubdomainResult) {
		// Call the original processor if there is one
		if originalProcessor != nil {
			originalProcessor(result)
		}

		// Add to the collected results
		resultsMutex.Lock()
		collectedResults = append(collectedResults, result)
		resultsMutex.Unlock()
	}

	// Simulate using active scan
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

	// Call activeScan function temporarily until StreamingActiveScan is implemented
	temporaryResults := activeScan(tempConfig)

	// Simulate calling the result processor
	for _, result := range temporaryResults {
		if config.ResultProcessor != nil {
			config.ResultProcessor(result)
		}
	}

	return collectedResults
}

// activeScan performs active subdomain enumeration using a wordlist
// Tries to find subdomains by adding words from the wordlist to the domain
func activeScan(config ActiveScanConfig) []models.SubdomainResult {
	var wordlist []string
	var err error

	// Load or download wordlist
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

	// Process resolvers
	var finalResolvers []string
	finalResolvers = processResolvers(config.Resolvers)

	// Set up HTTP client for takeover checks
	client := setupHTTPClient(config.Takeover, config.Proxy)

	var results []models.SubdomainResult
	cache := models.NewDNSCache()
	level := 1
	toScan := []string{config.Domain}

	// Channel for streaming results if enabled
	var streamChan chan models.SubdomainResult
	if config.StreamResults {
		streamChan = setupStreamChannel(config.ShowIP)
	} else {
		streamChan = nil
	}

	// For each recursive level
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

		// Process results of this level for the next level if recursive
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

// processResolvers processes the given resolvers
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

// setupHTTPClient sets up an HTTP client for takeover checks
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

// setupStreamChannel sets up a channel for streaming results
func setupStreamChannel(showIP bool) chan models.SubdomainResult {
	streamChan := make(chan models.SubdomainResult, 100)

	// Set up goroutine to process streaming results
	go func() {
		for result := range streamChan {
			output.DisplayResult(result, showIP)
		}
	}()

	return streamChan
}

// scanLevel performs scanning for one recursion level
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

	// Display total tasks to be performed
	totalTasks := len(toScan) * len(wordlist)
	fmt.Printf("» Checking %d subdomains\n", totalTasks)

	// Create progress bar
	bar := utils.CreateProgressBar(totalTasks)

	// Setup result writer for real-time display
	var resultWriter *output.ResultWriter
	resultWriter = output.NewResultWriter(bar, config.ShowIP)

	// Start progress bar
	bar.Start()

	// Create worker pool
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

	// Feed subdomains to workers
	go func() {
		for _, target := range toScan {
			for _, word := range wordlist {
				subdomain := word + "." + target
				subdomainChan <- subdomain
			}
		}
		close(subdomainChan)
	}()

	// Collect results
	go func() {
		wg.Wait()
		close(resultChan)
		if streamChan != nil && !config.Recursive {
			close(streamChan)
		}
	}()

	// Process and save results for this level
	for result := range resultChan {
		levelResults = append(levelResults, result)
	}

	bar.Finish()

	return levelResults
}
