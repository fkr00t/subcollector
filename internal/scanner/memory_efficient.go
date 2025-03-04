package scanner

import (
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/cheggaaa/pb/v3"
	"github.com/fkr00t/subcollector/internal/models"
	"github.com/fkr00t/subcollector/internal/utils"
)

// StreamingActiveScan performs active scanning with more efficient memory usage
// using streaming to read the wordlist and process results
func StreamingActiveScan(config StreamingActiveScanConfig) error {
	fmt.Printf("[*] Starting active streaming scan for %s...\n\n", config.Domain)

	// Initialize backoff if enabled
	var backoff *utils.ExponentialBackoff
	if config.BackoffConfig.Enabled {
		backoff = utils.NewExponentialBackoff(
			config.BackoffConfig.BaseDelay,
			config.BackoffConfig.MaxDelay,
			config.BackoffConfig.Factor,
			config.BackoffConfig.Jitter,
		)
	}

	// Set up DNS cache with LRU + TTL
	dnsCache := models.NewDNSCacheWithLRU(10000, 30*time.Minute)
	// Start automatic cache cleanup every 5 minutes
	dnsCache.StartCleanup(5 * time.Minute)

	// Set up HTTP client for takeover checks
	client := setupHTTPClient(config.Takeover, config.Proxy)

	// Process resolvers
	finalResolvers := processResolvers(config.Resolvers)

	// Perform scanning level by level (for recursive)
	level := 1
	toScan := []string{config.Domain}

	// Create a reusable worker pool
	workerPool := utils.NewWorkerPool(config.NumWorkers, config.NumWorkers*2)
	workerPool.Start()
	defer workerPool.Stop()

	// For each recursive level
	for len(toScan) > 0 && (config.Depth == -1 || level <= config.Depth) {
		fmt.Printf("[INF] Enumeration level %d: %d domains\n", level, len(toScan))

		// Create channel to send subdomains to worker pool
		taskQueue := make(chan string, 1000)

		// Goroutine to read wordlist and fill taskQueue
		go func() {
			defer close(taskQueue)

			for _, targetDomain := range toScan {
				var reader io.Reader
				var err error

				// Use wordlist reader if provided, otherwise read from file
				if config.WordlistReader != nil {
					reader = config.WordlistReader
				} else {
					if config.WordlistPath == "" {
						defaultWordlistURL := "https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Discovery/DNS/subdomains-top1million-110000.txt"
						reader, err = utils.FetchWordlistReaderFromURL(defaultWordlistURL)
					} else {
						reader, err = utils.LoadWordlistReader(config.WordlistPath)
					}

					if err != nil {
						fmt.Printf("Error: Failed to load wordlist: %v\n", err)
						return
					}
				}

				// Use buffer to read wordlist in chunks
				buffer := make([]byte, 8192)
				var word string

				for {
					n, err := reader.Read(buffer)
					if err == io.EOF {
						// Flush any remaining word at EOF
						if word != "" {
							subdomain := word + "." + targetDomain
							taskQueue <- subdomain
							word = ""
						}
						break
					}
					if err != nil {
						fmt.Printf("Error: Failed to read wordlist: %v\n", err)
						break
					}

					// Process chunk
					for i := 0; i < n; i++ {
						if buffer[i] == '\n' || buffer[i] == '\r' {
							if word != "" {
								subdomain := word + "." + targetDomain
								taskQueue <- subdomain
								word = ""
							}
						} else {
							word += string(buffer[i])
						}
					}
				}
			}
		}()

		// Setup dynamic progress bar
		bar := pb.New(0)
		bar.SetTemplateString(`{{ cyan "SCAN" }} {{ (cycle . "⠋" "⠙" "⠹" "⠸" "⠼" "⠴" "⠦" "⠧" "⠇" "⠏" ) }} {{ counters . }} {{ bar . "❰" "█" "▓" "░" "❱" }} {{ percent . }} {{ green (speed . "%s p/s") }}`)
		bar.SetMaxWidth(80)
		bar.Start()

		// Process subdomain tasks and collect discovered subdomains
		var discoveredSubdomains []string
		var mu sync.Mutex

		// Process subdomain from task queue
		go func() {
			for subdomain := range taskQueue {
				bar.Increment()

				// Use backoff if enabled
				if backoff != nil && config.BackoffConfig.Enabled {
					targetHost := utils.ExtractRootDomain(subdomain)

					// Check if we're being rate limited
					if backoff.IsRateLimited(targetHost, config.BackoffConfig.FailThreshold) {
						delay := backoff.NextDelay(targetHost)
						time.Sleep(delay)
					}
				}

				// Add the task to worker pool
				workerPool.AddTask(func() interface{} {
					// Check cache first
					if cachedResult, ok := dnsCache.Load(subdomain); ok {
						if cachedResult.Found {
							result := models.SubdomainResult{
								Subdomain: subdomain,
								IPs:       cachedResult.IPs,
							}

							// Check for takeover if enabled
							if config.Takeover && client != nil {
								CheckTakeover(client, &result)
							}

							// Add to discovered for recursive scanning
							if config.Recursive {
								mu.Lock()
								discoveredSubdomains = append(discoveredSubdomains, subdomain)
								mu.Unlock()
							}

							// Process the result
							if config.ResultProcessor != nil {
								config.ResultProcessor(result)
							}

							return result
						}
						return nil
					}

					// Perform DNS lookup
					var addresses []string
					var err error
					if len(finalResolvers) > 0 {
						// Try each resolver until one works
						for _, resolver := range finalResolvers {
							addresses, err = utils.LookupWithResolver(subdomain, resolver)
							if err == nil {
								break
							}
						}
					} else {
						// Use system default resolver
						addresses, err = utils.DefaultLookup(subdomain)
					}

					if err == nil {
						// Subdomain exists
						dnsCache.Store(subdomain, models.DNSResult{Found: true, IPs: addresses})

						result := models.SubdomainResult{
							Subdomain: subdomain,
						}

						if config.ShowIP {
							result.IPs = addresses
						}

						// Check for takeover if enabled
						if config.Takeover && client != nil {
							CheckTakeover(client, &result)
						}

						// Add to discovered for recursive scanning
						if config.Recursive {
							mu.Lock()
							discoveredSubdomains = append(discoveredSubdomains, subdomain)
							mu.Unlock()
						}

						// Process the result
						if config.ResultProcessor != nil {
							config.ResultProcessor(result)
						}

						// Update backoff - request succeeded
						if backoff != nil && config.BackoffConfig.Enabled {
							targetHost := utils.ExtractRootDomain(subdomain)
							backoff.AdaptiveDelay(targetHost, true)
						}

						return result
					} else {
						// Subdomain doesn't exist
						dnsCache.Store(subdomain, models.DNSResult{Found: false})

						// Update backoff - request failed
						if backoff != nil && config.BackoffConfig.Enabled {
							targetHost := utils.ExtractRootDomain(subdomain)
							backoff.AdaptiveDelay(targetHost, false)
						}

						return nil
					}
				})
			}
		}()

		// Read results from worker pool
		go func() {
			for result := range workerPool.Results() {
				if result != nil {
					// Results are already processed by the task function
				}
			}
		}()

		// Wait for all tasks to complete
		workerPool.Stop()
		bar.Finish()

		fmt.Printf("\n[INF] Level %d complete. Found %d subdomains.\n\n", level, len(discoveredSubdomains))

		// Setup for next level if recursive
		if config.Recursive && (config.Depth == -1 || level < config.Depth) {
			toScan = discoveredSubdomains
			level++
		} else {
			toScan = []string{}
		}
	}

	return nil
}

// ExtractRootDomain extracts the root domain for rate limiting purposes
func ExtractRootDomain(subdomain string) string {
	return utils.ExtractRootDomain(subdomain)
}
