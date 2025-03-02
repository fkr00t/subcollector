package main

import (
	"fmt"
	"os"

	"github.com/fkr00t/subcollector/internal/cli"
	"github.com/fkr00t/subcollector/internal/utils"
)

// main adalah titik masuk aplikasi
// Menjalankan perintah root dan menangani error
func main() {
	// Inisialisasi logger
	err := utils.InitGlobalLogger(utils.LoggerConfig{
		Level:        utils.LevelInfo, // Default level
		OutputFile:   "",              // Tidak menulis ke file secara default
		ColorEnabled: true,
		TimeFormat:   "2006-01-02 15:04:05",
	})

	if err != nil {
		fmt.Printf("Error initializing logger: %v\n", err)
		os.Exit(1)
	}

	// Log startup
	utils.Info("Starting Subcollector...")

	// Jalankan CLI
	if err := cli.Execute(); err != nil {
		utils.Error("Error executing command: %v", err)
		os.Exit(1)
	}
}
