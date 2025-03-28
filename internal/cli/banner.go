package cli

import (
	"fmt"
	"github.com/fatih/color"
)

var (
	blue    = color.New(color.FgBlue).SprintFunc()
	version = "v1.4.2"
)

// PrintBanner displays the application banner with its name and version
func PrintBanner() {
	fmt.Println(blue("   _____       __               ____          __            "))
	fmt.Println(blue("  / ___/__  __/ /_  _________  / / /__  _____/ /_____  _____"))
	fmt.Println(blue("  \\__ \\/ / / / __ \\/ ___/ __ \\/ / / _ \\/ ___/ __/ __ \\/ ___/"))
	fmt.Println(blue(" ___/ / /_/ / /_/ / /__/ /_/ / / /  __/ /__/ /_/ /_/ / /    "))
	fmt.Println(blue("/____/\\__,_/_.___/\\___/\\____/_/_/\\___/\\___/\\__/\\____/_/     "))
	fmt.Println(blue("                                      Subdomain Enumeration "))
	fmt.Println(blue("  ---------------------------------------------------------"))
	fmt.Printf("    Version: %s  |  Developed by fkr00t\n", version)
	fmt.Println("")
}

// ShowVersion displays the application version
func ShowVersion() {
	PrintBanner()
}
