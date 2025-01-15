package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/projectdiscovery/subfinder/v2/pkg/runner"
)

var (
	green   = color.New(color.FgGreen).SprintFunc()
	version = "v1.1.0" // Program version
)

// Structure for JSON output
type SubdomainResult struct {
	Subdomain string   `json:"subdomain"`
	IPs       []string `json:"ips,omitempty"` // Include IPs if -show-ip is enabled
}

type OutputJSON struct {
	Domain     string            `json:"domain"`
	Subdomains []SubdomainResult `json:"subdomains"`
}

// Clean domain from http:// or https://
func cleanDomain(domain string) string {
	domain = strings.TrimSpace(domain)
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimPrefix(domain, "www.")
	return domain
}

// Load wordlist from file
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

// Fetch wordlist from a URL
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

// Load resolvers from file
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
		if resolver != "" && !strings.HasPrefix(resolver, "#") { // Ignore empty lines and comments
			resolvers = append(resolvers, resolver)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return resolvers, nil
}

// DNS lookup using a specific resolver
func lookupWithResolver(domain string, resolver string) ([]string, error) {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{}
			return d.DialContext(ctx, "udp", resolver+":53") // Use port 53 for DNS
		},
	}
	return r.LookupHost(context.Background(), domain)
}

// Passive scanning using subfinder
func passiveScan(domain string) ([]string, error) {
	fmt.Printf("[INF] Starting passive scan for %s...\n\n", domain)

	options := &runner.Options{
		Threads:            10,   // Number of threads
		Timeout:            30,   // Timeout in seconds
		MaxEnumerationTime: 10,   // Maximum enumeration time
		Silent:             true, // Disable unnecessary logs
	}

	runnerInstance, err := runner.NewRunner(options)
	if err != nil {
		return nil, err
	}

	results, err := runnerInstance.EnumerateSingleDomain(domain, []io.Writer{io.Discard}) // Discard logs
	if err != nil {
		return nil, err
	}

	var subdomains []string
	for result := range results {
		subdomains = append(subdomains, result)
	}

	return subdomains, nil
}

// Active scanning with wordlist and resolvers
func activeScan(domain string, wordlistPath string, resolvers []string, rateLimit int, recursive bool, showIP bool) []SubdomainResult {
	fmt.Printf("[*] Starting active scan for %s...\n\n", domain)

	var wordlist []string
	var err error

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

	if rateLimit > 0 {
		fmt.Printf("[*] Rate limit set to %d ms\n", rateLimit)
	}

	if recursive {
		fmt.Println("[*] Recursive enumeration enabled")
	}

	if showIP {
		fmt.Println("[*] Showing IP addresses for found subdomains")
	}

	var results []SubdomainResult
	var wg sync.WaitGroup
	var mutex sync.Mutex

	var scan func(string)
	scan = func(target string) {
		for _, word := range wordlist {
			subdomain := word + "." + target
			wg.Add(1)
			go func(subdomain string) {
				defer wg.Done()
				var err error
				var addresses []string

				if len(resolvers) > 0 {
					for _, resolver := range resolvers {
						addresses, err = lookupWithResolver(subdomain, resolver)
						if err == nil {
							break
						}
					}
				} else {
					addresses, err = net.LookupHost(subdomain)
				}

				if err == nil {
					mutex.Lock()
					result := SubdomainResult{Subdomain: subdomain}
					if showIP {
						result.IPs = addresses
					}
					results = append(results, result)
					mutex.Unlock()

					if showIP {
						fmt.Printf("[%s] %s (IP: %v)\n", green("+"), subdomain, addresses)
					} else {
						fmt.Printf("[%s] %s\n", green("+"), subdomain)
					}

					if recursive {
						scan(subdomain)
					}
				}
				time.Sleep(time.Duration(rateLimit) * time.Millisecond)
			}(subdomain)
		}
	}

	scan(domain)
	wg.Wait()

	fmt.Println()

	return results
}

func main() {
	fmt.Println(`
 ▞▀▖   ▌  ▞▀▖▐            
 ▚▄ ▌ ▌▛▀▖▚▄ ▜▀ ▞▀▖▙▀▖▛▚▀▖
 ▖ ▌▌ ▌▌ ▌▖ ▌▐ ▖▌ ▌▌  ▌▐ ▌
 ▝▀ ▝▀▘▀▀ ▝▀  ▀ ▝▀ ▘  ▘▝ ▘

 Created by fkr00t | github: https://github.com/fkr00t
	`)

	if len(os.Args) == 1 {
		fmt.Printf("[INF] Current substorm version %s\n", version)
		fmt.Println("[FTL] Program exiting: no input list provided")
		return
	}

	domain := flag.String("d", "", "Target domain (e.g., example.com)")
	active := flag.Bool("active", false, "Enable active scanning")
	wordlist := flag.String("w", "", "Path to custom wordlist file (optional)")
	resolversFile := flag.String("r", "", "Path to custom DNS resolvers file")
	rateLimit := flag.Int("rl", 100, "Rate limit in milliseconds (default: 100)")
	recursive := flag.Bool("recursive", false, "Enable recursive enumeration")
	jsonOutput := flag.String("oJ", "", "Save results in JSON format (default: output.json)")
	output := flag.String("o", "", "Output results to file")
	showVersion := flag.Bool("version", false, "Show program version")
	showIP := flag.Bool("show-ip", false, "Show IP addresses for found subdomains")
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage of %s:\n", os.Args[0])
		fmt.Println("Options:")
		fmt.Println("  -d string")
		fmt.Println("        Target domain (e.g., example.com)")
		fmt.Println("  -active")
		fmt.Println("        Enable active scanning")
		fmt.Println("  -w string")
		fmt.Println("        Path to custom wordlist file (optional)")
		fmt.Println("  -r string")
		fmt.Println("        Path to custom DNS resolvers file")
		fmt.Println("  -rl int")
		fmt.Println("        Rate limit in milliseconds (default: 100)")
		fmt.Println("  -recursive")
		fmt.Println("        Enable recursive enumeration")
		fmt.Println("  -oJ string")
		fmt.Println("        Save results in JSON format (default: output.json)")
		fmt.Println("  -o string")
		fmt.Println("        Output results to file")
		fmt.Println("  -show-ip")
		fmt.Println("        Show IP addresses for found subdomains")
		fmt.Println("  -version")
		fmt.Println("        Show program version")
	}
	flag.Parse()

	if *showVersion {
		fmt.Printf("[INF] Current substorm version %s\n", version)
		return
	}

	if *domain == "" {
		flag.Usage()
		return
	}

	cleanedDomain := cleanDomain(*domain)
	fmt.Printf("[INF] Processing domain: %s\n", cleanedDomain)

	var resolvers []string
	if *resolversFile != "" {
		var err error
		resolvers, err = loadResolvers(*resolversFile)
		if err != nil {
			fmt.Println("[ERR] Failed to load resolvers file!")
			return
		}
		fmt.Printf("[INF] Using custom DNS resolvers: %v\n", resolvers)
	}

	var results []SubdomainResult
	if *active {
		results = activeScan(cleanedDomain, *wordlist, resolvers, *rateLimit, *recursive, *showIP)
	} else {
		subdomains, err := passiveScan(cleanedDomain)
		if err != nil {
			fmt.Println("[ERR]", err)
			return
		}
		for _, subdomain := range subdomains {
			results = append(results, SubdomainResult{Subdomain: subdomain})
		}

		fmt.Println("\n[INF] Enumeration results:")
		for _, result := range results {
			fmt.Println(result.Subdomain)
		}
	}

	if *jsonOutput != "" || *output != "" {
		outputFile := *output
		if *jsonOutput != "" {
			outputFile = *jsonOutput
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

		if *jsonOutput != "" {
			outputData := OutputJSON{
				Domain:     cleanedDomain,
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

	fmt.Println("\n[INF] Scanning completed.")
}
