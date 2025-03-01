package cli

import (
	"github.com/spf13/cobra"
	"subcollector/internal/scanner"
	"subcollector/internal/utils"
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
	Long:  "Subcollector adalah alat untuk menghitung subdomain menggunakan teknik pasif dan aktif.",
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
	Short: "Melakukan enumerasi subdomain secara pasif",
	Run: func(cmd *cobra.Command, args []string) {
		if versionFlag, _ := cmd.Flags().GetBool("version"); versionFlag {
			ShowVersion()
			return
		}

		if domain == "" && listPath == "" {
			cmd.Println("[ERR] Mohon tentukan domain (-d) atau daftar domain (-l)")
			return
		}

		handlePassiveCommand()
	},
}

var activeCmd = &cobra.Command{
	Use:   "active",
	Short: "Melakukan enumerasi subdomain secara aktif",
	Run: func(cmd *cobra.Command, args []string) {
		if versionFlag, _ := cmd.Flags().GetBool("version"); versionFlag {
			ShowVersion()
			return
		}

		if domain == "" && listPath == "" {
			cmd.Println("[ERR] Mohon tentukan domain (-d) atau daftar domain (-l)")
			return
		}

		handleActiveCommand()
	},
}

// Execute menjalankan command root
func Execute() error {
	return rootCmd.Execute()
}

// init menginisialisasi perintah CLI dan flag
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

// handlePassiveCommand menangani eksekusi perintah passive
func handlePassiveCommand() {
	var domains []string
	var err error

	if listPath != "" {
		domains, err = utils.LoadDomains(listPath)
		if err != nil {
			utils.PrintError("Gagal memuat daftar domain!")
			return
		}
	} else {
		domains = []string{domain}
	}

	// Konfigurasi untuk pemindaian pasif
	config := scanner.PassiveScanConfig{
		ShowIP:         showIP,
		StreamResults:  streamResults,
		OutputFile:     output,
		JsonOutputFile: jsonOutput,
	}

	// Jalankan pemindaian pasif untuk setiap domain
	for _, d := range domains {
		cleanedDomain := utils.CleanDomain(d)
		if cleanedDomain == "" {
			continue
		}

		config.Domain = cleanedDomain
		scanner.ExecutePassiveScan(config)
	}
}

// handleActiveCommand menangani eksekusi perintah active
func handleActiveCommand() {
	var domains []string
	var err error

	if listPath != "" {
		domains, err = utils.LoadDomains(listPath)
		if err != nil {
			utils.PrintError("Gagal memuat daftar domain!")
			return
		}
	} else {
		domains = []string{domain}
	}

	// Konfigurasi untuk pemindaian aktif
	config := scanner.ActiveScanConfig{
		WordlistPath:  wordlistPath,
		Resolvers:     resolvers,
		RateLimit:     rateLimit,
		Recursive:     recursive,
		ShowIP:        showIP,
		Depth:         depth,
		Takeover:      takeover,
		Proxy:         proxy,
		NumWorkers:    numWorkers,
		StreamResults: streamResults,
		//RealTimeDisplay: realTimeDisplay,
		OutputFile:     output,
		JsonOutputFile: jsonOutput,
	}

	// Jalankan pemindaian aktif untuk setiap domain
	for _, d := range domains {
		cleanedDomain := utils.CleanDomain(d)
		if cleanedDomain == "" {
			continue
		}

		config.Domain = cleanedDomain
		scanner.ExecuteActiveScan(config)
	}
}
