package cli

// setupFlags mengkonfigurasi semua flag untuk perintah CLI
func setupFlags() {
	// Root flags
	rootCmd.PersistentFlags().BoolP("version", "v", false, "Tampilkan informasi versi")
	//rootCmd.PersistentFlags().BoolP("silent", "q", false, "Mode silent - meminimalkan output ke konsol")

	// Passive command flags
	setupPassiveFlags()

	// Active command flags
	setupActiveFlags()
}

// setupPassiveFlags mengkonfigurasi flag untuk perintah passive
func setupPassiveFlags() {
	passiveCmd.Flags().BoolP("version", "v", false, "Tampilkan informasi versi")
	passiveCmd.Flags().StringVarP(&domain, "domain", "d", "", "Domain target (contoh: example.com)")
	passiveCmd.Flags().StringVarP(&listPath, "list", "l", "", "Path ke file yang berisi daftar domain")
	passiveCmd.Flags().StringVarP(&output, "output", "o", "", "Simpan hasil ke file (format teks)")
	passiveCmd.Flags().StringVarP(&jsonOutput, "json-output", "j", "", "Simpan hasil dalam format JSON")
	passiveCmd.Flags().BoolVarP(&showIP, "show-ip", "s", false, "Tampilkan alamat IP untuk subdomain yang ditemukan")
	passiveCmd.Flags().BoolVarP(&streamResults, "stream", "S", false, "Stream hasil ke file output (mengurangi penggunaan memori)")
}

// setupActiveFlags mengkonfigurasi flag untuk perintah active
func setupActiveFlags() {
	activeCmd.Flags().BoolP("version", "v", false, "Tampilkan informasi versi")
	activeCmd.Flags().StringVarP(&domain, "domain", "d", "", "Domain target (contoh: example.com)")
	activeCmd.Flags().StringVarP(&listPath, "list", "l", "", "Path ke file yang berisi daftar domain")
	activeCmd.Flags().StringVarP(&wordlistPath, "wordlist", "w", "", "Path ke file wordlist kustom")
	activeCmd.Flags().StringSliceVarP(&resolvers, "resolvers", "r", []string{}, "Resolver DNS kustom (contoh: 8.8.8.8,1.1.1.1 atau path ke file)")
	activeCmd.Flags().IntVarP(&rateLimit, "rate-limit", "t", 100, "Rate limit dalam milidetik")
	activeCmd.Flags().BoolVarP(&recursive, "recursive", "R", false, "Aktifkan enumerasi rekursif")
	activeCmd.Flags().BoolVarP(&showIP, "show-ip", "s", false, "Tampilkan alamat IP untuk subdomain yang ditemukan")
	activeCmd.Flags().StringVarP(&output, "output", "o", "", "Simpan hasil ke file (format teks)")
	activeCmd.Flags().StringVarP(&jsonOutput, "json-output", "j", "", "Simpan hasil dalam format JSON")
	activeCmd.Flags().BoolVarP(&takeover, "takeover", "T", false, "Aktifkan deteksi pengambilalihan subdomain")
	activeCmd.Flags().StringVarP(&proxy, "proxy", "p", "", "URL proxy untuk request HTTP (contoh: http://proxy:8080)")
	activeCmd.Flags().IntVarP(&depth, "depth", "D", 1, "Kedalaman rekursi untuk pemindaian aktif (-1 untuk tidak terbatas)")
	activeCmd.Flags().IntVarP(&numWorkers, "workers", "W", 10, "Jumlah worker konkuren (default: 10)")
	activeCmd.Flags().BoolVarP(&streamResults, "stream", "S", false, "Stream hasil ke file output (mengurangi penggunaan memori)")
	//activeCmd.Flags().BoolVarP(&realTimeDisplay, "real-time", "E", true, "Tampilkan hasil secara real-time sambil mempertahankan progress bar (default: true)")
}
