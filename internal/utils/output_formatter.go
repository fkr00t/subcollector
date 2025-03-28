package utils

import (
	"fmt"
	"github.com/fatih/color"
	"strings"
)

// OutputColors configures the colors used for output
var (
	InfoColor      = color.New(color.FgCyan)
	InfoBoldColor  = color.New(color.FgCyan, color.Bold)
	SuccessColor   = color.New(color.FgGreen)
	SuccessBold    = color.New(color.FgGreen, color.Bold)
	WarningColor   = color.New(color.FgYellow)
	WarningBold    = color.New(color.FgYellow, color.Bold)
	ErrorColor     = color.New(color.FgRed)
	ErrorBold      = color.New(color.FgRed, color.Bold)
	HighlightColor = color.New(color.FgHiWhite, color.Bold)
	SubtleColor    = color.New(color.FgWhite, color.Faint)
)

// FormatterLevel defines the importance level of output for the formatter
type FormatterLevel int

const (
	LevelNormalFormat FormatterLevel = iota
	LevelImportantFormat
	LevelWarningFormat
	LevelErrorFormat
	LevelSuccessFormat
)

// OutputSymbol returns a symbol for the output level
func OutputSymbol(level FormatterLevel) string {
	switch level {
	case LevelNormalFormat:
		return "→"
	case LevelImportantFormat:
		return "●"
	case LevelWarningFormat:
		return "⚠"
	case LevelErrorFormat:
		return "✖"
	case LevelSuccessFormat:
		return "✓"
	default:
		return "•"
	}
}

// PrintFormatted prints a message with format and color based on level
func PrintFormatted(message string, level FormatterLevel) {
	symbol := OutputSymbol(level)

	var colorPrinter *color.Color
	switch level {
	case LevelNormalFormat:
		colorPrinter = InfoColor
	case LevelImportantFormat:
		colorPrinter = InfoBoldColor
	case LevelWarningFormat:
		colorPrinter = WarningColor
	case LevelErrorFormat:
		colorPrinter = ErrorColor
	case LevelSuccessFormat:
		colorPrinter = SuccessColor
	default:
		colorPrinter = InfoColor
	}

	colorPrinter.Printf(" %s %s\n", symbol, message)
}

// PrintSectionHeader prints a header for a section with an attractive format
func PrintSectionHeader(title string) {
	width := 80
	padding := (width - len(title) - 4) / 2

	if padding < 1 {
		padding = 1
	}

	line := strings.Repeat("─", width)
	paddedTitle := fmt.Sprintf("%s %s %s",
		strings.Repeat("─", padding),
		strings.ToUpper(title),
		strings.Repeat("─", padding+(width-len(title)-4)%2))

	fmt.Println()
	SubtleColor.Println(line)
	HighlightColor.Println(paddedTitle)
	SubtleColor.Println(line)
	fmt.Println()
}

// PrintResultSummary displays a summary of scan results with a clear format
func PrintResultSummary(domain string, totalChecked, found int, duration string) {
	fmt.Println()
	HighlightColor.Printf(" SCAN SUMMARY \n\n")

	InfoColor.Printf(" %-15s: ", "Domain")
	fmt.Println(domain)

	InfoColor.Printf(" %-15s: ", "Total Checked")
	fmt.Println(totalChecked)

	InfoColor.Printf(" %-15s: ", "Subdomains")
	SuccessBold.Println(found)

	InfoColor.Printf(" %-15s: ", "Time")
	fmt.Println(duration)

	fmt.Println()
	SubtleColor.Println(strings.Repeat("─", 80))
	fmt.Println()
}

// PrintProcessStep prints a process step with a step number
func PrintProcessStep(stepNum int, stepDesc string) {
	InfoBoldColor.Printf(" %d. ", stepNum)
	fmt.Println(stepDesc)
}

// PrintStageBegin prints the beginning of a process stage
func PrintStageBegin(stageName string) {
	InfoBoldColor.Printf(" ▶ Starting: %s\n", stageName)
}

// PrintStageEnd prints the end of a process stage
func PrintStageEnd(stageName string, success bool) {
	if success {
		SuccessColor.Printf(" ✓ Completed: %s\n", stageName)
	} else {
		ErrorColor.Printf(" ✗ Failed: %s\n", stageName)
	}
}

// PrintSubdomainResult prints a subdomain result with additional information
func PrintSubdomainResult(subdomain string, ips []string, takeover string, showIP bool) {
	// Check if subdomain was found and takeover detected
	if takeover != "" {
		WarningBold.Printf(" [!] ")
		fmt.Printf("%s ", subdomain)
		WarningColor.Printf("[%s]\n", takeover)
	} else {
		SuccessColor.Printf(" [+] ")
		fmt.Println(subdomain)
	}

	// Show IP if needed
	if showIP && len(ips) > 0 {
		SubtleColor.Printf("     IP: %s\n", strings.Join(ips, ", "))
	}
}

// FormatProgressBar formats and prints a progress bar
func FormatProgressBar(current, total int, prefix string, width int) {
	percent := float64(current) * 100 / float64(total)
	filled := int(float64(width) * float64(current) / float64(total))
	bar := strings.Repeat("█", filled) + strings.Repeat("░", width-filled)

	fmt.Printf("\r %s [%s] %.1f%% (%d/%d)", prefix, bar, percent, current, total)

	if current >= total {
		fmt.Println()
	}
}

// FormatSubdomain formats a subdomain with highlighting on the prefix
func FormatSubdomain(subdomain, domain string) string {
	if strings.HasSuffix(subdomain, "."+domain) {
		prefix := strings.TrimSuffix(subdomain, "."+domain)
		return fmt.Sprintf("%s.%s", HighlightColor.Sprint(prefix), domain)
	}
	return subdomain
}
