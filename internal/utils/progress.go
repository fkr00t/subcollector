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

// CreateProgressBar membuat progress bar dengan desain neon cyberpunk modern
func CreateProgressBar(totalTasks int) *pb.ProgressBar {
	// Template dengan spinner di awal dan ETA di akhir
	// Menggunakan cycle untuk membuat efek spinner
	template := `{{ cyan (cycle . "⠋" "⠙" "⠹" "⠸" "⠼" "⠴" "⠦" "⠧" "⠇" "⠏") }} {{ blue "┃" }} {{ green (bar . "█" "▓" "▒" "░" " ") }} {{ blue "┃" }} {{ magenta "⬢" }} {{ percent . }}% {{ magenta (speed . "%s/s") }} {{ yellow "ETA:" }} {{ yellow (rtime . ) }} {{ green "⟴" }}`

	// Konfigurasi progress bar dengan animasi halus
	bar := pb.New(totalTasks)
	bar.SetTemplateString(template)
	bar.SetWidth(50)                          // Lebar besar untuk detail visual
	bar.SetMaxWidth(140)                      // Maksimum lebar untuk tampilan dramatis
	bar.SetRefreshRate(time.Millisecond * 40) // Animasi sangat halus

	return bar
}

// ShowLoading menampilkan spinner dengan estetika cyberpunk modern
func ShowLoading(stopChan chan bool) {
	// Spinner neon dengan efek berdenyut
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

			// Tampilan neon cyberpunk dengan warna hijau konsisten
			fmt.Printf("\r%s %s %s %s ",
				green(leftPulse),
				green("◉ PROCESSING"), // Warna diubah ke hijau untuk konsistensi
				green(rightPulse),
				blue("⬣"), // Ikon hexagonal modern
			)

			i++
			time.Sleep(70 * time.Millisecond) // Kecepatan tinggi untuk efek neon
		}
	}
}

// PrintError menampilkan pesan error dengan gaya cyberpunk
func PrintError(message string) {
	fmt.Printf("\n %s %s %s\n\n", red("⮾"), red("ERROR:"), message)
}

// PrintInfo menampilkan pesan informasi
func PrintInfo(message string) {
	fmt.Printf("\n %s %s %s\n\n", blue("⬡"), blue("INFO:"), message)
}

// PrintSuccess menampilkan pesan sukses
func PrintSuccess(message string) {
	fmt.Printf("\n %s %s %s\n\n", green("⮹"), green("SUCCESS:"), message)
}

// ShowProgressBar menampilkan progress bar sederhana dengan desain cyberpunk modern
func ShowProgressBar(current, total int, prefix string) {
	width := 40 // Lebar besar untuk efek visual
	percent := float64(current) * 100 / float64(total)
	completed := int(float64(width) * float64(current) / float64(total))

	// Bar dengan efek modern menggunakan karakter solid
	bar := strings.Repeat("█", completed) + strings.Repeat(" ", width-completed)
	coloredBar := green(bar) // Bar diwarnai hijau untuk konsistensi

	// Output bergaya cyberpunk dengan gradasi visual
	fmt.Printf("\r%s %s %s %s %.1f%% %s",
		blue("⟟"),    // Batas kiri neon
		coloredBar,   // Bar dengan warna hijau
		blue("⟠"),    // Batas kanan neon
		magenta("⬢"), // Ikon hexagon
		percent,
		green("⟴"), // Ikon futuristik
	)

	if current >= total {
		fmt.Printf(" %s\n", green("⮸")) // Ikon selesai
	}
}
