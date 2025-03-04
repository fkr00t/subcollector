package cli

import (
	"github.com/fkr00t/subcollector/internal/scanner"
	"github.com/fkr00t/subcollector/internal/utils"
	"github.com/spf13/cobra"
)

var (
	// Global flags
	domain, listPath, output, jsonOutput, wordlistPath, proxy   string
	showIP, recursive, takeover, streamResults, realTimeDisplay bool
	rateLimit, depth, numWorkers                                int
	resolvers                                                   []string
)

var rootCmd = &cobra.Command{
	Use:   "subcollector",
	Short: "Subcollector - Subdomain Enumeration Tool",
	Long:  "Subcollector is a tool for enumerating subdomains using passive and active techniques.",
	Run: func(cmd *cobra.Command, args []string) {
		if versionFlag, _ := cmd.Flags().GetBool("version"); versionFlag {
			ShowVersion()
			return
		}
		PrintBanner()
		cmd.Help()
	},
}

var passiveCmd = &cobra.Command{
	Use:   "passive",
	Short: "Perform passive subdomain enumeration",
	Run: func(cmd *cobra.Command, args []string) {
		if versionFlag, _ := cmd.Flags().GetBool("version"); versionFlag {
			ShowVersion()
			return
		}

		if domain == "" && listPath == "" {
			cmd.Println("[ERR] Please specify a domain (-d) or a domain list (-l)")
			return
		}

		handlePassiveCommand()
	},
}

var activeCmd = &cobra.Command{
	Use:   "active",
	Short: "Perform active subdomain enumeration",
	Run: func(cmd *cobra.Command, args []string) {
		if versionFlag, _ := cmd.Flags().GetBool("version"); versionFlag {
			ShowVersion()
			return
		}

		if domain == "" && listPath == "" {
			cmd.Println("[ERR] Please specify a domain (-d) or a domain list (-l)")
			return
		}

		handleActiveCommand()
	},
}

// Execute runs the root command
func Execute() error {
	return rootCmd.Execute()
}

// init initializes CLI commands and flags
func init() {
	rootCmd.AddCommand(activeCmd)
	rootCmd.AddCommand(passiveCmd)

	rootCmd.SetHelpCommand(&cobra.Command{
		Use:    "no-help",
		Hidden: true,
	})

	rootCmd.CompletionOptions.DisableDefaultCmd = true

	setupFlags()
}

// handlePassiveCommand handles execution of the passive command
func handlePassiveCommand() {
	var domains []string
	var err error

	if listPath != "" {
		domains, err = utils.LoadDomains(listPath)
		if err != nil {
			utils.PrintError("Failed to load domain list!")
			return
		}
	} else {
		domains = []string{domain}
	}

	// Configuration for passive scanning
	config := scanner.PassiveScanConfig{
		ShowIP:         showIP,
		StreamResults:  streamResults,
		OutputFile:     output,
		JsonOutputFile: jsonOutput,
	}

	// Run passive scanning for each domain
	for _, d := range domains {
		cleanedDomain := utils.CleanDomain(d)
		if cleanedDomain == "" {
			continue
		}

		config.Domain = cleanedDomain
		scanner.ExecutePassiveScan(config)
	}
}

// handleActiveCommand handles execution of the active command
func handleActiveCommand() {
	var domains []string
	var err error

	if listPath != "" {
		domains, err = utils.LoadDomains(listPath)
		if err != nil {
			utils.PrintError("Failed to load domain list!")
			return
		}
	} else {
		domains = []string{domain}
	}

	// Configuration for active scanning
	config := scanner.ActiveScanConfig{
		WordlistPath:   wordlistPath,
		Resolvers:      resolvers,
		RateLimit:      rateLimit,
		Recursive:      recursive,
		ShowIP:         showIP,
		Depth:          depth,
		Takeover:       takeover,
		Proxy:          proxy,
		NumWorkers:     numWorkers,
		StreamResults:  streamResults,
		OutputFile:     output,
		JsonOutputFile: jsonOutput,
	}

	// Run active scanning for each domain
	for _, d := range domains {
		cleanedDomain := utils.CleanDomain(d)
		if cleanedDomain == "" {
			continue
		}

		config.Domain = cleanedDomain
		scanner.ExecuteActiveScan(config)
	}
}
