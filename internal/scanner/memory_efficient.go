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

// StreamingActiveScan melakukan pemindaian aktif dengan penggunaan memori yang lebih efisien
// menggunakan streaming untuk membaca wordlist dan memproses hasil
func StreamingActiveScan(config StreamingActiveScanConfig) error {
	fmt.Printf("[*] Memulai pemindaian aktif streaming untuk %s...\n\n", config.Domain)

	// Inisialisasi backoff jika diaktifkan
	var backoff *utils.ExponentialBackoff
	if config.BackoffConfig.Enabled {
		backoff = utils.NewExponentialBackoff(
			config.BackoffConfig.BaseDelay,
			config.BackoffConfig.MaxDelay,
			config.BackoffConfig.Factor,
			config.BackoffConfig.Jitter,
		)
	}

	// Siapkan DNS cache dengan LRU + TTL
	dnsCache := models.NewDNSCacheWithLRU(10000, 30*time.Minute)
	// Mulai pembersihan otomatis cache setiap 5 menit
	dnsCache.StartCleanup(5 * time.Minute)

	// Siapkan HTTP client untuk pemeriksaan takeover
	client := setupHTTPClient(config.Takeover, config.Proxy)

	// Proses resolver
	finalResolvers := processResolvers(config.Resolvers)

	// Lakukan pemindaian level per level (untuk rekursif)
	level := 1
	toScan := []string{config.Domain}

	// Buat worker pool yang bisa digunakan kembali
	workerPool := utils.NewWorkerPool(config.NumWorkers, config.NumWorkers*2)
	workerPool.Start()
	defer workerPool.Stop()

	// Untuk setiap level rekursif
	for len(toScan) > 0 && (config.Depth == -1 || level <= config.Depth) {
		fmt.Printf("[INF] Enumerasi level %d: %d domain\n", level, len(toScan))

		// Buat channel untuk mengirim subdomain ke worker pool
		taskQueue := make(chan string, 1000)

		// Goroutine untuk membaca wordlist dan mengisi taskQueue
		go func() {
			defer close(taskQueue)

			for _, targetDomain := range toScan {
				var reader io.Reader
				var err error

				// Gunakan wordlist reader jika disediakan, jika tidak baca dari file
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
						fmt.Printf("Error: Gagal memuat wordlist: %v\n", err)
						return
					}
				}

				// Gunakan buffer untuk membaca wordlist dalam chunk
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
						fmt.Printf("Error: Gagal membaca wordlist: %v\n", err)
						break
					}

					// Proses chunk
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

		// Setup progress bar dinamis
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

		fmt.Printf("\n[INF] Level %d complete. Ditemukan %d subdomain.\n\n", level, len(discoveredSubdomains))

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
