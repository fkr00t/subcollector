package utils

import (
	"fmt"
	"strings"
	"time"

	"github.com/cheggaaa/pb/v3"
	"github.com/fatih/color"
)

var (
	blue    = color.New(color.FgBlue).SprintFunc()
	green   = color.New(color.FgGreen).SprintFunc()
	yellow  = color.New(color.FgYellow).SprintFunc()
	red     = color.New(color.FgRed).SprintFunc()
	magenta = color.New(color.FgMagenta).SprintFunc()
	cyan    = color.New(color.FgCyan).SprintFunc()
)

// CreateProgressBar creates a progress bar with a modern neon cyberpunk design
func CreateProgressBar(totalTasks int) *pb.ProgressBar {
	// Template with spinner at the beginning and ETA at the end
	// Using cycle to create a spinner effect
	template := `{{ cyan (cycle . "⠋" "⠙" "⠹" "⠸" "⠼" "⠴" "⠦" "⠧" "⠇" "⠏") }} {{ blue "┃" }} {{ green (bar . "█" "▓" "▒" "░" " ") }} {{ blue "┃" }} {{ magenta "⬢" }} {{ percent . }}% {{ magenta (speed . "%s/s") }} {{ yellow "ETA:" }} {{ yellow (rtime . ) }} {{ green "⟴" }}`

	// Configure progress bar with smooth animation
	bar := pb.New(totalTasks)
	bar.SetTemplateString(template)
	bar.SetWidth(50)                          // Large width for visual detail
	bar.SetMaxWidth(140)                      // Maximum width for dramatic display
	bar.SetRefreshRate(time.Millisecond * 40) // Very smooth animation

	return bar
}

// ShowLoading displays a spinner with modern cyberpunk aesthetics
func ShowLoading(stopChan chan bool) {
	// Neon spinner with pulsing effect
	pulseChars := []string{" ", "▂", "▃", "▄", "▅", "▆", "▇", "█", "▇", "▆", "▅", "▄"}

	i := 0
	for {
		select {
		case <-stopChan:
			fmt.Print("\r\033[K") // Clear the line
			return
		default:
			leftPulse := pulseChars[i%len(pulseChars)]
			rightPulse := pulseChars[(i+4)%len(pulseChars)]

			// Cyberpunk neon display with consistent green color
			fmt.Printf("\r%s %s %s %s ",
				green(leftPulse),
				green("◉ PROCESSING"), // Color changed to green for consistency
				green(rightPulse),
				blue("⬣"), // Modern hexagonal icon
			)

			i++
			time.Sleep(70 * time.Millisecond) // High speed for neon effect
		}
	}
}

// PrintError displays an error message with cyberpunk style
func PrintError(message string) {
	fmt.Printf("\n %s %s %s\n\n", red("⮾"), red("ERROR:"), message)
}

// PrintInfo displays an information message
func PrintInfo(message string) {
	fmt.Printf("\n %s %s %s\n\n", blue("⬡"), blue("INFO:"), message)
}

// PrintSuccess displays a success message
func PrintSuccess(message string) {
	fmt.Printf("\n %s %s %s\n\n", green("⮹"), green("SUCCESS:"), message)
}

// ShowProgressBar displays a simple progress bar with modern cyberpunk design
func ShowProgressBar(current, total int, prefix string) {
	width := 40 // Large width for visual effect
	percent := float64(current) * 100 / float64(total)
	completed := int(float64(width) * float64(current) / float64(total))

	// Bar with modern effect using solid characters
	bar := strings.Repeat("█", completed) + strings.Repeat(" ", width-completed)
	coloredBar := green(bar) // Bar colored green for consistency

	// Cyberpunk-styled output with visual gradation
	fmt.Printf("\r%s %s %s %s %.1f%% %s",
		blue("⟟"),    // Left neon border
		coloredBar,   // Bar with green color
		blue("⟠"),    // Right neon border
		magenta("⬢"), // Hexagon icon
		percent,
		green("⟴"), // Futuristic icon
	)

	if current >= total {
		fmt.Printf(" %s\n", green("⮸")) // Completion icon
	}
}
