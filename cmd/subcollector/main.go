package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/cheggaaa/pb/v3"
	"github.com/fatih/color"
	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
	"github.com/spf13/cobra"
)

var (
	green   = color.New(color.FgGreen).SprintFunc()
	blue    = color.New(color.FgBlue).SprintFunc()
	yellow  = color.New(color.FgYellow).SprintFunc()
	version = "v1.3.0"
)

// SubdomainResult represents a single subdomain finding with associated data
type SubdomainResult struct {
	Subdomain string   `json:"subdomain"`          // The discovered subdomain
	IPs       []string `json:"ips,omitempty"`      // IP addresses associated with the subdomain
	Takeover  string   `json:"takeover,omitempty"` // Potential service that could be taken over
}

// OutputJSON represents the complete output structure for JSON serialization
type OutputJSON struct {
	Domain     string            `json:"domain"`     // The main domain being scanned
	Subdomains []SubdomainResult `json:"subdomains"` // List of discovered subdomains
}

// DNSResult represents the result of a DNS lookup, used in the cache
type DNSResult struct {
	Found bool     // Whether the subdomain exists
	IPs   []string // IP addresses associated with the subdomain if found
}

// Map of patterns used to detect potential subdomain takeovers
// Each entry represents a service and a string pattern indicating vulnerability
var takeoverPatterns = map[string]string{
	"aws":       "NoSuchBucket",
	"azure":     "The specified blob does not exist",
	"github":    "There isn't a GitHub Pages site here",
	"heroku":    "No such app",
	"shopify":   "Sorry, this shop is currently unavailable",
	"fastly":    "Fastly error: unknown domain",
	"pantheon":  "The gods are wise, but do not know of this site",
	"tumblr":    "Whatever you were looking for doesn't currently exist at this address",
	"wordpress": "Do you want to register",
	"teamwork":  "Oops - We didn't find your site",
	"helpjuice": "We could not find what you're looking for",
	"helpscout": "No settings were found for this company",
	"cargo":     "The specified Cargo site could not be found",
	"feedpress": "The feed has not been found",
	"surge":     "project not found",
	"webflow":   "The page you are looking for doesn't exist or has been moved",
	"jazzhr":    "This account no longer active",
}

// ResultWriter manages real-time output of results while keeping the progress bar intact
type ResultWriter struct {
	bar     *pb.ProgressBar   // Reference to the progress bar
	mutex   *sync.Mutex       // Mutex to ensure thread safety
	results []SubdomainResult // Buffer to store results
	showIP  bool              // Whether to show IP addresses
}

// NewResultWriter creates a new ResultWriter instance
func NewResultWriter(bar *pb.ProgressBar, showIP bool) *ResultWriter {
	return &ResultWriter{
		bar:     bar,
		mutex:   &sync.Mutex{},
		results: []SubdomainResult{},
		showIP:  showIP,
	}
}

// WriteResult writes a new result while preserving the progress bar
func (rw *ResultWriter) WriteResult(result SubdomainResult) {
	rw.mutex.Lock()
	defer rw.mutex.Unlock()

	// Store the result
	rw.results = append(rw.results, result)

	// Save the current state of the progress bar
	barString := rw.bar.String()

	// Clear the line
	fmt.Print("\r\033[K")

	// Print the result
	if rw.showIP {
		fmt.Printf("[%s] %s (IP: %v)\n", green("+"), result.Subdomain, result.IPs)
	} else {
		fmt.Printf("[%s] %s\n", green("+"), result.Subdomain)
	}

	if result.Takeover != "" {
		fmt.Printf("[%s] Possible takeover for %s: %s\n", yellow("!"), result.Subdomain, result.Takeover)
	}

	// Restore the progress bar on the next line
	fmt.Print(barString)
}

// GetResults returns all stored results
func (rw *ResultWriter) GetResults() []SubdomainResult {
	rw.mutex.Lock()
	defer rw.mutex.Unlock()
	return rw.results
}

// cleanDomain removes common prefixes and whitespace from a domain
// This ensures consistent domain format for processing
func cleanDomain(domain string) string {
	domain = strings.TrimSpace(domain)
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimPrefix(domain, "www.")
	return domain
}

// loadDomains reads a list of domains from a file
// Each domain should be on a new line
// Returns a slice of domains and any error encountered
func loadDomains(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var domains []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		domain := strings.TrimSpace(scanner.Text())
		if domain != "" {
			domains = append(domains, domain)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return domains, nil
}

// loadWordlist reads a wordlist from a file for active scanning
// Each word should be on a new line
// Returns a slice of words and any error encountered
func loadWordlist(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var wordlist []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if word != "" {
			wordlist = append(wordlist, word)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return wordlist, nil
}

// fetchWordlistFromURL downloads a wordlist from a URL
// Used when no local wordlist is specified
// Returns a slice of words and any error encountered
func fetchWordlistFromURL(url string) ([]string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to download wordlist: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to download wordlist: status code %d", resp.StatusCode)
	}

	var wordlist []string
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if word != "" {
			wordlist = append(wordlist, word)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read wordlist: %v", err)
	}

	return wordlist, nil
}

// loadResolvers reads a list of DNS resolvers from a file
// Each resolver should be on a new line
// Lines starting with # are treated as comments
// Returns a slice of resolver addresses and any error encountered
func loadResolvers(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var resolvers []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		resolver := strings.TrimSpace(scanner.Text())
		if resolver != "" && !strings.HasPrefix(resolver, "#") {
			resolvers = append(resolvers, resolver)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return resolvers, nil
}

// lookupWithResolver performs a DNS lookup using a specific resolver
// This allows for more control over the DNS resolution process
// Returns a slice of IP addresses and any error encountered
func lookupWithResolver(domain string, resolver string) ([]string, error) {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{}
			return d.DialContext(ctx, "udp", resolver+":53")
		},
	}
	return r.LookupHost(context.Background(), domain)
}

// passiveScan performs passive subdomain enumeration using subfinder
// Uses external sources to discover subdomains without direct interaction with the target
// Returns a slice of SubdomainResult and any error encountered
func passiveScan(domain string, showIP bool) ([]SubdomainResult, error) {
	fmt.Printf("[INF] Starting passive scan for %s...\n\n", domain)

	stopChan := make(chan bool)
	go showLoading(stopChan)

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

	var subdomains []SubdomainResult
	for result := range results {
		subdomainResult := SubdomainResult{Subdomain: result}

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

// worker is a concurrent worker function for active scanning
// Processes subdomains from a channel and sends results to another channel
// Each worker handles DNS lookups and optional takeover checks
func worker(
	subdomainChan <-chan string, // Channel to receive subdomains to check
	resultChan chan<- SubdomainResult, // Channel to send results
	resolvers []string, // List of DNS resolvers to use
	cache *sync.Map, // Cache to avoid duplicate lookups
	client *http.Client, // HTTP client for takeover detection
	bar *pb.ProgressBar, // Progress bar for visual feedback
	resultWriter *ResultWriter, // Writer for real-time result display
	wg *sync.WaitGroup, // WaitGroup for synchronization
	showIP bool, // Whether to include IP addresses in results
	rateLimit int, // Rate limiting in milliseconds between requests
	streamOutput chan<- SubdomainResult, // Channel for streaming results (can be nil)
) {
	defer wg.Done()

	for subdomain := range subdomainChan {
		var result SubdomainResult

		// Cek cache dulu
		if val, ok := cache.Load(subdomain); ok {
			// Use cached DNS result if available
			dnsRes := val.(DNSResult)
			if dnsRes.Found {
				result = SubdomainResult{Subdomain: subdomain, IPs: dnsRes.IPs}
				if client != nil {
					// Check for potential takeover
					checkTakeover(client, &result)
				}
				resultChan <- result

				// Write result in real-time
				if resultWriter != nil {
					resultWriter.WriteResult(result)
				}

				if streamOutput != nil {
					streamOutput <- result
				}
			}
		} else {
			var addresses []string
			var err error
			if len(resolvers) > 0 {
				// Try each resolver until one works
				for _, resolver := range resolvers {
					addresses, err = lookupWithResolver(subdomain, resolver)
					if err == nil {
						break
					}
				}
			} else {
				// Use system default resolver
				addresses, err = net.LookupHost(subdomain)
			}

			if err == nil {
				// Subdomain exists
				cache.Store(subdomain, DNSResult{Found: true, IPs: addresses})
				result = SubdomainResult{Subdomain: subdomain}
				if showIP {
					result.IPs = addresses
				}
				if client != nil {
					// Check for potential takeover
					checkTakeover(client, &result)
				}
				resultChan <- result

				// Write result in real-time
				if resultWriter != nil {
					resultWriter.WriteResult(result)
				}

				if streamOutput != nil {
					streamOutput <- result
				}
			} else {
				// Subdomain doesn't exist
				cache.Store(subdomain, DNSResult{Found: false})
			}
		}

		// Update progress bar tanpa print ke console
		bar.Increment()

		// Rate limiter
		if rateLimit > 0 {
			time.Sleep(time.Duration(rateLimit) * time.Millisecond)
		}
	}
}

// checkTakeover checks if a subdomain is vulnerable to takeover
// Sends an HTTP request and checks for patterns indicating takeover possibility
func checkTakeover(client *http.Client, result *SubdomainResult) {
	resp, err := client.Get("http://" + result.Subdomain)
	if err == nil {
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err == nil {
			for service, pattern := range takeoverPatterns {
				if strings.Contains(string(body), pattern) {
					result.Takeover = service
					break
				}
			}
		}
	}
}

// activeScan performs active subdomain enumeration using a wordlist
// Attempts to find subdomains by appending words from a wordlist to the domain
// Returns a slice of SubdomainResult
func activeScan(
	domain string, // Domain to scan
	wordlistPath string, // Path to wordlist file
	resolvers []string, // DNS resolvers to use
	rateLimit int, // Rate limiting in milliseconds
	recursive bool, // Whether to recursively scan discovered subdomains
	showIP bool, // Whether to include IP addresses in results
	depth int, // Recursion depth (-1 for unlimited)
	takeover bool, // Whether to check for subdomain takeover
	proxy string, // HTTP proxy to use
	numWorkers int, // Number of concurrent workers
	streamResults bool, // Whether to stream results as they're found
	realTimeDisplay bool, // Whether to display results in real-time
) []SubdomainResult {
	fmt.Printf("[*] Starting active scan for %s...\n\n", domain)

	var wordlist []string
	var err error

	// Load or download wordlist
	if wordlistPath == "" {
		defaultWordlistURL := "https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Discovery/DNS/subdomains-top1million-110000.txt"
		wordlist, err = fetchWordlistFromURL(defaultWordlistURL)
		if err != nil {
			fmt.Printf("Error: Failed to fetch default wordlist: %v\n", err)
			return nil
		}
	} else {
		wordlist, err = loadWordlist(wordlistPath)
		if err != nil {
			fmt.Println("Error: Wordlist file not found!")
			return nil
		}
		fmt.Printf("[*] Using custom wordlist: %s\n", wordlistPath)
	}

	if rateLimit != 100 {
		fmt.Printf("[*] Rate limit set to %d ms\n", rateLimit)
	}

	if recursive {
		fmt.Println("[*] Recursive enumeration enabled")
	}

	if showIP {
		fmt.Println("[*] Showing IP addresses for found subdomains")
	}

	if numWorkers != 10 {
		fmt.Printf("[*] Using %d concurrent workers\n", numWorkers)
	}

	// Process resolvers
	var finalResolvers []string
	if len(resolvers) == 1 && strings.Contains(resolvers[0], ".") && !strings.Contains(resolvers[0], ",") {
		fileResolvers, err := loadResolvers(resolvers[0])
		if err != nil {
			fmt.Println("[ERR] Failed to load resolvers file!")
			return nil
		}
		finalResolvers = fileResolvers
		fmt.Printf("[*] Using custom DNS resolvers from file: %v\n", finalResolvers)
	} else if len(resolvers) > 0 {
		finalResolvers = resolvers
		fmt.Printf("[*] Using custom DNS resolvers: %v\n", finalResolvers)
	}

	// Set up HTTP client for takeover checks
	var client *http.Client
	if takeover {
		if proxy != "" {
			proxyURL, err := url.Parse(proxy)
			if err != nil {
				fmt.Println("[ERR] Invalid proxy URL:", err)
				return nil
			}
			transport := &http.Transport{
				Proxy: http.ProxyURL(proxyURL),
			}
			client = &http.Client{Transport: transport, Timeout: 5 * time.Second}
		} else {
			client = &http.Client{Timeout: 5 * time.Second}
		}
	} else {
		client = nil
	}

	var results []SubdomainResult
	cache := &sync.Map{}
	level := 1
	toScan := []string{domain}

	// Channel for streaming results if enabled
	var streamChan chan SubdomainResult
	if streamResults {
		streamChan = make(chan SubdomainResult, 100)
		// Set up a goroutine to process streamed results
		go func() {
			for result := range streamChan {
				if showIP {
					fmt.Printf("[%s] %s (IP: %v)\n", green("+"), result.Subdomain, result.IPs)
				} else {
					fmt.Printf("[%s] %s\n", green("+"), result.Subdomain)
				}
				if result.Takeover != "" {
					fmt.Printf("[%s] Possible takeover for %s: %s\n", yellow("!"), result.Subdomain, result.Takeover)
				}
			}
		}()
	} else {
		streamChan = nil
	}

	// Untuk tiap level rekursif
	for len(toScan) > 0 && (depth == -1 || level <= depth) {
		fmt.Printf("[INF] Enumerating level %d: %d domains\n", level, len(toScan))
		var levelResults []SubdomainResult
		var wg sync.WaitGroup
		subdomainChan := make(chan string, 100)
		resultChan := make(chan SubdomainResult, 100)

		// Tampilkan total task yang akan dikerjakan
		totalTasks := len(toScan) * len(wordlist)
		fmt.Printf("[INF] Total subdomains to check: %d\n", totalTasks)

		// Buat template custom untuk progress bar
		animatedTmpl := `{{ cyan "SCAN" }} {{ (cycle . "⠋" "⠙" "⠹" "⠸" "⠼" "⠴" "⠦" "⠧" "⠇" "⠏" ) }} {{ counters . }} {{ bar . "❰" "█" "▓" "░" "❱" }} {{ percent . }} {{ green (speed . "%s p/s") }}`

		// Buat progress bar dengan konfigurasi yang lebih baik
		bar := pb.New(totalTasks)
		bar.SetTemplateString(animatedTmpl)
		bar.SetWidth(50)                           // Set lebar yang konsisten
		bar.SetMaxWidth(80)                        // Batasi lebar maksimum
		bar.SetRefreshRate(time.Millisecond * 100) // Refresh rate untuk animasi yang halus
		bar.Start()

		// Setup result writer for real-time display
		var resultWriter *ResultWriter
		if realTimeDisplay {
			resultWriter = NewResultWriter(bar, showIP)
		} else {
			resultWriter = nil
		}

		bar.Start()

		// Buat worker pool
		for i := 0; i < numWorkers; i++ {
			wg.Add(1)
			go worker(subdomainChan, resultChan, finalResolvers, cache, client, bar, resultWriter, &wg, showIP, rateLimit, streamChan)
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
			if streamChan != nil && !recursive {
				close(streamChan)
			}
		}()

		// Process and store results for this level
		for result := range resultChan {
			levelResults = append(levelResults, result)
		}

		bar.Finish()

		// Tampilkan ringkasan hasil
		fmt.Printf("\n[INF] Found %d subdomains at level %d\n\n", len(levelResults), level)

		// Output hasil jika tidak dalam real-time
		if !realTimeDisplay && !streamResults {
			for _, result := range levelResults {
				if showIP {
					fmt.Printf("[%s] %s (IP: %v)\n", green("+"), result.Subdomain, result.IPs)
				} else {
					fmt.Printf("[%s] %s\n", green("+"), result.Subdomain)
				}
				if result.Takeover != "" {
					fmt.Printf("[%s] Possible takeover for %s: %s\n", yellow("!"), result.Subdomain, result.Takeover)
				}
			}
		} else if realTimeDisplay {
			// Hasil sudah ditampilkan secara real-time oleh ResultWriter
			fmt.Println("[INF] All results displayed in real-time")
		}

		// Process results of this level for next level if recursive
		results = append(results, levelResults...)
		if recursive && (depth == -1 || level < depth) {
			toScan = []string{}
			for _, res := range levelResults {
				toScan = append(toScan, res.Subdomain)
			}
			level++
		} else {
			toScan = []string{}
		}
	}

	if streamChan != nil && recursive {
		close(streamChan)
	}

	return results
}

// batchSaveResults saves results in batches to avoid storing all results in memory
// This function processes a channel of results and writes them directly to a file
func batchSaveResults(outputFile string, jsonFormat bool, domain string, resultsChan <-chan SubdomainResult, doneChan chan<- bool) {
	file, err := os.Create(outputFile)
	if err != nil {
		fmt.Println("[ERR] Failed to create output file!")
		doneChan <- false
		return
	}
	defer file.Close()

	if jsonFormat {
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
	} else {
		// Simple text format
		for result := range resultsChan {
			file.WriteString(fmt.Sprintf("%s\n", result.Subdomain))
		}
	}

	doneChan <- true
}

// saveResults saves the scan results to a file
// Supports both text and JSON formats
func saveResults(output, jsonOutput, domain string, results []SubdomainResult) {
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
		return
	}
	defer file.Close()

	if jsonOutput != "" {
		outputData := OutputJSON{
			Domain:     domain,
			Subdomains: results,
		}
		jsonData, err := json.MarshalIndent(outputData, "", "    ")
		if err != nil {
			fmt.Println("[ERR] Failed to create JSON output!")
			return
		}
		file.Write(jsonData)
		fmt.Printf("[INF] Results saved to %s (JSON format)\n", outputFile)
	} else {
		for _, result := range results {
			file.WriteString(fmt.Sprintf("%s\n", result.Subdomain))
		}
		fmt.Printf("[INF] Results saved to %s (text format)\n", outputFile)
	}
}

// showVersion displays the current version of the tool
func showVersion() {
	printBanner()
}

// printBanner displays the tool's banner with name and version
// printBanner displays the tool's banner with name and version
func printBanner() {
	fmt.Println(blue("   _____       __               ____          __            "))
	fmt.Println(blue("  / ___/__  __/ /_  _________  / / /__  _____/ /_____  _____"))
	fmt.Println(blue("  \\__ \\/ / / / __ \\/ ___/ __ \\/ / / _ \\/ ___/ __/ __ \\/ ___/"))
	fmt.Println(blue(" ___/ / /_/ / /_/ / /__/ /_/ / / /  __/ /__/ /_/ /_/ / /    "))
	fmt.Println(blue("/____/\\__,_/_.___/\\___/\\____/_/_/\\___/\\___/\\__/\\____/_/     "))
	fmt.Println(blue("                                      Subdomain Enumeration "))
	fmt.Println(blue("  ---------------------------------------------------------"))
	fmt.Printf("    Version: %s  |  Developed by fkr00t\n", version)
	fmt.Println("")
}

// showLoading displays an animated spinner during scanning
func showLoading(stopChan chan bool) {
	spinner := []string{"-", "\\", "|", "/"}
	i := 0
	for {
		select {
		case <-stopChan:
			fmt.Print("\r")
			return
		default:
			fmt.Printf("\r[%s] Scanning...", spinner[i])
			i = (i + 1) % len(spinner)
			time.Sleep(100 * time.Millisecond)
		}
	}
}

// Root command for the CLI application
var rootCmd = &cobra.Command{
	Use:   "subcollector",
	Short: "Subcollector - Subdomain Enumeration Tool",
	Long:  "Subcollector is a tool for enumerating subdomains using passive and active techniques.",
	Run: func(cmd *cobra.Command, args []string) {
		if versionFlag, _ := cmd.Flags().GetBool("version"); versionFlag {
			showVersion()
			return
		}
		printBanner()
		cmd.Help()
	},
}

// Command for passive scanning
var passiveCmd = &cobra.Command{
	Use:   "passive",
	Short: "Perform passive subdomain enumeration",
	Run: func(cmd *cobra.Command, args []string) {
		if versionFlag, _ := cmd.Flags().GetBool("version"); versionFlag {
			showVersion()
			return
		}

		domain, _ := cmd.Flags().GetString("domain")
		listPath, _ := cmd.Flags().GetString("list")
		output, _ := cmd.Flags().GetString("output")
		jsonOutput, _ := cmd.Flags().GetString("json-output")
		showIP, _ := cmd.Flags().GetBool("show-ip")
		streamOutput, _ := cmd.Flags().GetBool("stream")

		if domain == "" && listPath == "" {
			fmt.Println("[ERR] Please specify a domain (-d) or a domain list (-l)")
			return
		}

		var domains []string
		if listPath != "" {
			loadedDomains, err := loadDomains(listPath)
			if err != nil {
				fmt.Println("[ERR] Failed to load domains list!")
				return
			}
			domains = loadedDomains
		} else {
			domains = []string{domain}
		}

		// If streaming results to output file directly
		var resultsChan chan SubdomainResult
		var doneChan chan bool

		if streamOutput && (output != "" || jsonOutput != "") {
			resultsChan = make(chan SubdomainResult, 100)
			doneChan = make(chan bool)

			outputFile := output
			if jsonOutput != "" {
				outputFile = jsonOutput
				go batchSaveResults(outputFile, true, domains[0], resultsChan, doneChan)
			} else {
				go batchSaveResults(outputFile, false, domains[0], resultsChan, doneChan)
			}
		}

		var allResults []SubdomainResult
		for _, d := range domains {
			cleanedDomain := cleanDomain(d)
			if cleanedDomain == "" {
				continue
			}

			results, err := passiveScan(cleanedDomain, showIP)
			if err != nil {
				fmt.Printf("[ERR] Passive scan failed for %s: %v\n", cleanedDomain, err)
				continue
			}

			// Stream results if enabled
			if streamOutput && resultsChan != nil {
				for _, result := range results {
					resultsChan <- result
				}
			} else {
				allResults = append(allResults, results...)

				for _, result := range results {
					if showIP {
						fmt.Printf("[%s] %s (IP: %v)\n", green("+"), result.Subdomain, result.IPs)
					} else {
						fmt.Printf("[%s] %s\n", green("+"), result.Subdomain)
					}
				}

				if (output != "" || jsonOutput != "") && !streamOutput {
					saveResults(output, jsonOutput, cleanedDomain, results)
				}
			}
		}

		// Close channel and wait for file writing to complete
		if streamOutput && resultsChan != nil {
			close(resultsChan)
			success := <-doneChan
			if success {
				outputFile := output
				if jsonOutput != "" {
					outputFile = jsonOutput
				}
				fmt.Printf("[INF] Results saved to %s\n", outputFile)
			}
		}
	},
}

// Command for active scanning
var activeCmd = &cobra.Command{
	Use:   "active",
	Short: "Perform active subdomain enumeration",
	Run: func(cmd *cobra.Command, args []string) {
		if versionFlag, _ := cmd.Flags().GetBool("version"); versionFlag {
			showVersion()
			return
		}

		domain, _ := cmd.Flags().GetString("domain")
		listPath, _ := cmd.Flags().GetString("list")
		wordlistPath, _ := cmd.Flags().GetString("wordlist")
		resolvers, _ := cmd.Flags().GetStringSlice("resolvers")
		rateLimit, _ := cmd.Flags().GetInt("rate-limit")
		recursive, _ := cmd.Flags().GetBool("recursive")
		showIP, _ := cmd.Flags().GetBool("show-ip")
		output, _ := cmd.Flags().GetString("output")
		jsonOutput, _ := cmd.Flags().GetString("json-output")
		takeover, _ := cmd.Flags().GetBool("takeover")
		proxy, _ := cmd.Flags().GetString("proxy")
		depth, _ := cmd.Flags().GetInt("depth")
		numWorkers, _ := cmd.Flags().GetInt("workers")
		streamResults, _ := cmd.Flags().GetBool("stream")
		realTimeDisplay, _ := cmd.Flags().GetBool("real-time")

		if domain == "" && listPath == "" {
			fmt.Println("[ERR] Please specify a domain (-d) or a domain list (-l)")
			return
		}

		var domains []string
		if listPath != "" {
			loadedDomains, err := loadDomains(listPath)
			if err != nil {
				fmt.Println("[ERR] Failed to load domains list!")
				return
			}
			domains = loadedDomains
		} else {
			domains = []string{domain}
		}

		// Configure result streaming to file if enabled
		var resultsChan chan SubdomainResult
		var doneChan chan bool

		if streamResults && (output != "" || jsonOutput != "") {
			resultsChan = make(chan SubdomainResult, 100)
			doneChan = make(chan bool)

			outputFile := output
			if jsonOutput != "" {
				outputFile = jsonOutput
				go batchSaveResults(outputFile, true, domains[0], resultsChan, doneChan)
			} else {
				go batchSaveResults(outputFile, false, domains[0], resultsChan, doneChan)
			}
		}

		var allResults []SubdomainResult
		for _, d := range domains {
			cleanedDomain := cleanDomain(d)
			if cleanedDomain == "" {
				continue
			}

			results := activeScan(
				cleanedDomain,
				wordlistPath,
				resolvers,
				rateLimit,
				recursive,
				showIP,
				depth,
				takeover,
				proxy,
				numWorkers,
				streamResults,
				realTimeDisplay,
			)

			if results == nil {
				continue
			}

			if !streamResults {
				allResults = append(allResults, results...)
				if output != "" || jsonOutput != "" {
					saveResults(output, jsonOutput, cleanedDomain, results)
				}
			}
		}

		// Close channel and wait for file writing to complete if streaming
		if streamResults && resultsChan != nil {
			close(resultsChan)
			success := <-doneChan
			if success {
				outputFile := output
				if jsonOutput != "" {
					outputFile = jsonOutput
				}
				fmt.Printf("[INF] Results saved to %s\n", outputFile)
			}
		}
	},
}

// init initializes the CLI commands and flags
func init() {
	rootCmd.AddCommand(activeCmd)
	rootCmd.AddCommand(passiveCmd)

	rootCmd.SetHelpCommand(&cobra.Command{
		Use:    "no-help",
		Hidden: true,
	})

	rootCmd.CompletionOptions.DisableDefaultCmd = true

	rootCmd.PersistentFlags().BoolP("version", "v", false, "Show version information")
	passiveCmd.Flags().BoolP("version", "v", false, "Show version information")
	activeCmd.Flags().BoolP("version", "v", false, "Show version information")

	// Passive scan flags
	passiveCmd.Flags().StringP("domain", "d", "", "Target domain (e.g., example.com)")
	passiveCmd.Flags().StringP("list", "l", "", "Path to file containing list of domains")
	passiveCmd.Flags().StringP("output", "o", "", "Output results to file (text format)")
	passiveCmd.Flags().StringP("json-output", "j", "", "Save results in JSON format")
	passiveCmd.Flags().BoolP("show-ip", "s", false, "Show IP addresses for found subdomains")
	passiveCmd.Flags().BoolP("stream", "S", false, "Stream results to output file (reduces memory usage)")

	// Active scan flags
	activeCmd.Flags().StringP("domain", "d", "", "Target domain (e.g., example.com)")
	activeCmd.Flags().StringP("list", "l", "", "Path to file containing list of domains")
	activeCmd.Flags().StringP("wordlist", "w", "", "Path to custom wordlist file")
	activeCmd.Flags().StringSliceP("resolvers", "r", []string{}, "Custom DNS resolvers (e.g., 8.8.8.8,1.1.1.1 or path to a file)")
	activeCmd.Flags().IntP("rate-limit", "t", 100, "Rate limit in milliseconds")
	activeCmd.Flags().BoolP("recursive", "R", false, "Enable recursive enumeration")
	activeCmd.Flags().BoolP("show-ip", "s", false, "Show IP addresses for found subdomains")
	activeCmd.Flags().StringP("output", "o", "", "Output results to file (text format)")
	activeCmd.Flags().StringP("json-output", "j", "", "Save results in JSON format")
	activeCmd.Flags().BoolP("takeover", "T", false, "Enable subdomain takeover detection")
	activeCmd.Flags().StringP("proxy", "p", "", "Proxy URL for HTTP requests (e.g., http://proxy:8080)")
	activeCmd.Flags().IntP("depth", "D", 1, "Recursion depth for active scanning (-1 for unlimited)")
	activeCmd.Flags().IntP("workers", "W", 10, "Number of concurrent workers (default: 10)")
	activeCmd.Flags().BoolP("stream", "S", false, "Stream results to output file (reduces memory usage)")
	activeCmd.Flags().BoolP("real-time", "E", true, "Display results in real-time while maintaining progress bar (default: true)")
}

// main is the entry point of the application
// It executes the root command and handles any errors
func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
