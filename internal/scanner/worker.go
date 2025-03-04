package scanner

import (
	"net/http"
	"sync"
	"time"

	"github.com/cheggaaa/pb/v3"
	"github.com/fkr00t/subcollector/internal/models"
	"github.com/fkr00t/subcollector/internal/output"
	"github.com/fkr00t/subcollector/internal/utils"
)

// Worker is a concurrent worker function for active scanning
// Processes subdomains from a channel and sends results to another channel
// Each worker handles DNS lookups and optional takeover checks
func Worker(
	subdomainChan <-chan string, // Channel to receive subdomains to check
	resultChan chan<- models.SubdomainResult, // Channel to send results
	resolvers []string, // List of DNS resolvers to use
	cache *models.DNSCache, // Cache to avoid duplicate lookups
	client *http.Client, // HTTP client for takeover detection
	bar *pb.ProgressBar, // Progress bar for visual feedback
	resultWriter *output.ResultWriter, // Writer for real-time result display
	wg *sync.WaitGroup, // WaitGroup for synchronization
	showIP bool, // Whether to include IP addresses in results
	rateLimit int, // Rate limiting in milliseconds between requests
	streamOutput chan<- models.SubdomainResult, // Channel for streaming results
) {
	defer wg.Done()

	for subdomain := range subdomainChan {
		var result models.SubdomainResult

		// Check cache first
		if cachedResult, ok := cache.Load(subdomain); ok {
			// Use cached DNS result if available
			if cachedResult.Found {
				result = models.SubdomainResult{Subdomain: subdomain, IPs: cachedResult.IPs}
				if client != nil {
					// Check for potential takeover
					CheckTakeover(client, &result)
				}
				resultChan <- result

				// Write results in real-time
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
				// Try each resolver until one succeeds
				for _, resolver := range resolvers {
					addresses, err = utils.LookupWithResolver(subdomain, resolver)
					if err == nil {
						break
					}
				}
			} else {
				// Use default system resolver
				addresses, err = utils.DefaultLookup(subdomain)
			}

			if err == nil {
				// Subdomain exists
				cache.Store(subdomain, models.DNSResult{Found: true, IPs: addresses})
				result = models.SubdomainResult{Subdomain: subdomain}
				if showIP {
					result.IPs = addresses
				}
				if client != nil {
					// Check for potential takeover
					CheckTakeover(client, &result)
				}
				resultChan <- result

				// Write results in real-time
				if resultWriter != nil {
					resultWriter.WriteResult(result)
				}

				if streamOutput != nil {
					streamOutput <- result
				}
			} else {
				// Subdomain doesn't exist
				cache.Store(subdomain, models.DNSResult{Found: false})
			}
		}

		// Update progress bar
		bar.Increment()

		// Rate limiter
		if rateLimit > 0 {
			time.Sleep(time.Duration(rateLimit) * time.Millisecond)
		}
	}
}
