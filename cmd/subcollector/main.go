package main

import (
	"bufio"
	"context"
	"encoding/json"
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
	"github.com/spf13/cobra"
)

var (
	green   = color.New(color.FgGreen).SprintFunc()
	blue    = color.New(color.FgBlue).SprintFunc()
	magenta = color.New(color.FgMagenta).SprintFunc()
	yellow  = color.New(color.FgYellow).SprintFunc()
	version = "v1.2.2" // Installed version
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

// Load domains from file
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
		if resolver != "" && !strings.HasPrefix(resolver, "#") { // Ignore comments
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
func passiveScan(domain string, showIP bool) ([]SubdomainResult, error) {
	fmt.Printf("[INF] Starting passive scan for %s...\n\n", domain)

	// Channel to stop the loading animation
	stopChan := make(chan bool)
	go showLoading(stopChan) // Start the loading animation

	options := &runner.Options{
		Threads:            10,   // Number of threads
		Timeout:            30,   // Timeout in seconds
		MaxEnumerationTime: 10,   // Maximum enumeration time
		Silent:             true, // Disable unnecessary logs
	}

	runnerInstance, err := runner.NewRunner(options)
	if err != nil {
		stopChan <- true // Stop the loading animation
		return nil, err
	}

	results, err := runnerInstance.EnumerateSingleDomain(domain, []io.Writer{io.Discard}) // Discard logs
	if err != nil {
		stopChan <- true // Stop the loading animation
		return nil, err
	}

	var subdomains []SubdomainResult
	for result := range results {
		subdomainResult := SubdomainResult{Subdomain: result}

		if showIP {
			// Perform DNS resolution to get IP addresses
			ips, err := net.LookupHost(result)
			if err == nil {
				subdomainResult.IPs = ips
			}
		}

		subdomains = append(subdomains, subdomainResult)
	}

	stopChan <- true // Stop the loading animation
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

	if rateLimit != 100 { // 100 adalah nilai default
		fmt.Printf("[*] Rate limit set to %d ms\n", rateLimit)
	}

	if recursive {
		fmt.Println("[*] Recursive enumeration enabled")
	}

	if showIP {
		fmt.Println("[*] Showing IP addresses for found subdomains")
	}

	var finalResolvers []string
	if len(resolvers) == 1 && strings.Contains(resolvers[0], ".") && !strings.Contains(resolvers[0], ",") {
		// If input is a file
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

				if len(finalResolvers) > 0 {
					for _, resolver := range finalResolvers {
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

// Save results to file
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

func showVersion() {
	fmt.Printf("Subcollector version: %s\n", version)
}

func printBanner() {
	banner := `
      ▌        ▜▜       ▐        
▞▀▘▌ ▌▛▀▖▞▀▖▞▀▖▐▐ ▞▀▖▞▀▖▜▀ ▞▀▖▙▀▖
▝▀▖▌ ▌▌ ▌▌ ▖▌ ▌▐▐ ▛▀ ▌ ▖▐ ▖▌ ▌▌  
▀▀ ▝▀▘▀▀ ▝▀ ▝▀  ▘▘▝▀▘▝▀  ▀ ▝▀ ▘
 Created by fkr00t | github: https://github.com/fkr00t
	`

	// Split banner into lines
	lines := strings.Split(banner, "\n")

	// Apply colors to each line
	for i, line := range lines {
		switch i {
		case 1, 2, 3, 4:
			fmt.Println(blue(line)) // Lines 1-4 in blue
		case 5:
			fmt.Println(magenta(line)) // Line 5 in magenta
		case 6:
			fmt.Println(yellow(line)) // Line 6 in yellow
		default:
			fmt.Println(line) // Other lines without color
		}
	}
}

// Root command
var rootCmd = &cobra.Command{
	Use:   "subcollector",
	Short: "Subdomain enumeration tool",
	Long:  `Subcollector is a tool for enumerating subdomains using passive and active methods.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Check if version flag is set
		if showVersionFlag, _ := cmd.Flags().GetBool("version"); showVersionFlag {
			showVersion()
			return
		}

		// Display colored banner
		printBanner()

		// Show help if no subcommand is provided
		cmd.Help()
	},
}

// Passive command
var passiveCmd = &cobra.Command{
	Use:   "passive",
	Short: "Perform passive subdomain enumeration",
	Long:  `Perform passive subdomain enumeration using public data sources.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Check if version flag is set
		if showVersionFlag, _ := cmd.Flags().GetBool("version"); showVersionFlag {
			showVersion()
			return
		}

		// Display colored banner
		printBanner()

		// Check if domain or domain list is provided
		domain, _ := cmd.Flags().GetString("domain")
		domainList, _ := cmd.Flags().GetString("list")

		var domains []string
		if domainList != "" {
			// Load domains from file
			var err error
			domains, err = loadDomains(domainList)
			if err != nil {
				fmt.Printf("[ERR] Failed to load domain list: %v\n", err)
				return
			}
		} else if domain != "" {
			// Use single domain
			domains = []string{domain}
		} else {
			// No domain provided
			fmt.Println("[ERR] Domain or domain list is required for passive enumeration.")
			cmd.Help()
			return
		}

		// Process each domain
		for _, domain := range domains {
			cleanedDomain := cleanDomain(domain)
			fmt.Printf("[INF] Processing domain: %s\n", cleanedDomain)

			showIP, _ := cmd.Flags().GetBool("show-ip")
			output, _ := cmd.Flags().GetString("output")
			jsonOutput, _ := cmd.Flags().GetString("json-output")

			results, err := passiveScan(cleanedDomain, showIP)
			if err != nil {
				fmt.Println("[ERR]", err)
				continue
			}

			fmt.Println("\n[INF] Enumeration results:")
			for _, result := range results {
				if showIP && len(result.IPs) > 0 {
					fmt.Printf("%s (IP: %v)\n", result.Subdomain, result.IPs)
				} else {
					fmt.Println(result.Subdomain)
				}
			}

			if output != "" || jsonOutput != "" {
				saveResults(output, jsonOutput, cleanedDomain, results)
			}
		}
	},
}

// Function to display loading animation
func showLoading(stopChan chan bool) {
	frames := []string{"|", "/", "-", "\\"}
	i := 0
	for {
		select {
		case <-stopChan:
			fmt.Printf("\r") // Clear the line
			return
		default:
			fmt.Printf("\r[%s] Scanning...", frames[i])
			time.Sleep(100 * time.Millisecond)
			i = (i + 1) % len(frames)
		}
	}
}

// Active command
var activeCmd = &cobra.Command{
	Use:   "active",
	Short: "Perform active subdomain enumeration",
	Long:  `Perform active subdomain enumeration using brute-forcing and DNS resolution.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Check if version flag is set
		if showVersionFlag, _ := cmd.Flags().GetBool("version"); showVersionFlag {
			showVersion()
			return
		}

		// Display colored banner
		printBanner()

		// Check if domain or domain list is provided
		domain, _ := cmd.Flags().GetString("domain")
		domainList, _ := cmd.Flags().GetString("list")

		var domains []string
		if domainList != "" {
			// Load domains from file
			var err error
			domains, err = loadDomains(domainList)
			if err != nil {
				fmt.Printf("[ERR] Failed to load domain list: %v\n", err)
				return
			}
		} else if domain != "" {
			// Use single domain
			domains = []string{domain}
		} else {
			// No domain provided
			fmt.Println("[ERR] Domain or domain list is required for active enumeration.")
			cmd.Help()
			return
		}

		// Process each domain
		for _, domain := range domains {
			cleanedDomain := cleanDomain(domain)
			fmt.Printf("[INF] Processing domain: %s\n", cleanedDomain)

			wordlist, _ := cmd.Flags().GetString("wordlist")
			resolvers, _ := cmd.Flags().GetStringSlice("resolvers")
			rateLimit, _ := cmd.Flags().GetInt("rate-limit")
			recursive, _ := cmd.Flags().GetBool("recursive")
			showIP, _ := cmd.Flags().GetBool("show-ip")
			output, _ := cmd.Flags().GetString("output")
			jsonOutput, _ := cmd.Flags().GetString("json-output")

			results := activeScan(cleanedDomain, wordlist, resolvers, rateLimit, recursive, showIP)

			if output != "" || jsonOutput != "" {
				saveResults(output, jsonOutput, cleanedDomain, results)
			}
		}
	},
}

func init() {
	// Add subcommands in the desired order
	rootCmd.AddCommand(activeCmd)
	rootCmd.AddCommand(passiveCmd)

	// Disable the default help command
	rootCmd.SetHelpCommand(&cobra.Command{
		Use:    "no-help", // This command will not be shown
		Hidden: true,      // Hide the command from help/usage
	})

	// Remove the completion command
	rootCmd.CompletionOptions.DisableDefaultCmd = true

	// Add version flag to root command
	rootCmd.PersistentFlags().BoolP("version", "v", false, "Show version information")

	// Add version flag to passive command
	passiveCmd.Flags().BoolP("version", "v", false, "Show version information")

	// Add version flag to active command
	activeCmd.Flags().BoolP("version", "v", false, "Show version information")

	// Flags for passive command
	passiveCmd.Flags().StringP("domain", "d", "", "Target domain (e.g., example.com)")
	passiveCmd.Flags().StringP("list", "l", "", "Path to file containing list of domains")
	passiveCmd.Flags().StringP("output", "o", "", "Output results to file (text format)")
	passiveCmd.Flags().StringP("json-output", "j", "", "Save results in JSON format")

	// Flags for active command
	activeCmd.Flags().StringP("domain", "d", "", "Target domain (e.g., example.com)")
	activeCmd.Flags().StringP("list", "l", "", "Path to file containing list of domains")
	activeCmd.Flags().StringP("wordlist", "w", "", "Path to custom wordlist file")
	activeCmd.Flags().StringSliceP("resolvers", "r", []string{}, "Custom DNS resolvers (e.g., 8.8.8.8,1.1.1.1 or path to a file)")
	activeCmd.Flags().IntP("rate-limit", "t", 100, "Rate limit in milliseconds")
	activeCmd.Flags().BoolP("recursive", "R", false, "Enable recursive enumeration")
	activeCmd.Flags().BoolP("show-ip", "s", false, "Show IP addresses for found subdomains")
	activeCmd.Flags().StringP("output", "o", "", "Output results to file (text format)")
	activeCmd.Flags().StringP("json-output", "j", "", "Save results in JSON format")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
