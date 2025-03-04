package cli

// setupFlags configures all flags for CLI commands
func setupFlags() {
	// Root flags
	rootCmd.PersistentFlags().BoolP("version", "v", false, "Show version information")

	// Passive command flags
	setupPassiveFlags()

	// Active command flags
	setupActiveFlags()
}

// setupPassiveFlags configures flags for the passive command
func setupPassiveFlags() {
	passiveCmd.Flags().BoolP("version", "v", false, "Show version information")
	passiveCmd.Flags().StringVarP(&domain, "domain", "d", "", "Target domain (example: example.com)")
	passiveCmd.Flags().StringVarP(&listPath, "list", "l", "", "Path to a file containing a list of domains")
	passiveCmd.Flags().StringVarP(&output, "output", "o", "", "Save results to a file (text format)")
	passiveCmd.Flags().StringVarP(&jsonOutput, "json-output", "j", "", "Save results in JSON format")
	passiveCmd.Flags().BoolVarP(&showIP, "show-ip", "s", false, "Display IP addresses for found subdomains")
	passiveCmd.Flags().BoolVarP(&streamResults, "stream", "S", false, "Stream results to output file (reduces memory usage)")
}

// setupActiveFlags configures flags for the active command
func setupActiveFlags() {
	activeCmd.Flags().BoolP("version", "v", false, "Show version information")
	activeCmd.Flags().StringVarP(&domain, "domain", "d", "", "Target domain (example: example.com)")
	activeCmd.Flags().StringVarP(&listPath, "list", "l", "", "Path to a file containing a list of domains")
	activeCmd.Flags().StringVarP(&wordlistPath, "wordlist", "w", "", "Path to a custom wordlist file")
	activeCmd.Flags().StringSliceVarP(&resolvers, "resolvers", "r", []string{}, "Custom DNS resolvers (example: 8.8.8.8,1.1.1.1 or path to a file)")
	activeCmd.Flags().IntVarP(&rateLimit, "rate-limit", "t", 100, "Rate limit in milliseconds")
	activeCmd.Flags().BoolVarP(&recursive, "recursive", "R", false, "Enable recursive enumeration")
	activeCmd.Flags().BoolVarP(&showIP, "show-ip", "s", false, "Display IP addresses for found subdomains")
	activeCmd.Flags().StringVarP(&output, "output", "o", "", "Save results to a file (text format)")
	activeCmd.Flags().StringVarP(&jsonOutput, "json-output", "j", "", "Save results in JSON format")
	activeCmd.Flags().BoolVarP(&takeover, "takeover", "T", false, "Enable subdomain takeover detection")
	activeCmd.Flags().StringVarP(&proxy, "proxy", "p", "", "HTTP proxy URL (example: http://proxy:8080)")
	activeCmd.Flags().IntVarP(&depth, "depth", "D", 1, "Recursion depth for active scan (-1 for unlimited)")
	activeCmd.Flags().IntVarP(&numWorkers, "workers", "W", 10, "Number of concurrent workers (default: 10)")
	activeCmd.Flags().BoolVarP(&streamResults, "stream", "S", false, "Stream results to output file (reduces memory usage)")
}
