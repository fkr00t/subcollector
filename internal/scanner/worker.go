package scanner

import (
	"net/http"
	"sync"
	"time"

	"github.com/cheggaaa/pb/v3"
	"subcollector/internal/models"
	"subcollector/internal/output"
	"subcollector/internal/utils"
)

// Worker adalah fungsi worker konkuren untuk pemindaian aktif
// Memproses subdomain dari channel dan mengirim hasil ke channel lain
// Setiap worker menangani pencarian DNS dan pemeriksaan takeover opsional
func Worker(
	subdomainChan <-chan string, // Channel untuk menerima subdomain untuk diperiksa
	resultChan chan<- models.SubdomainResult, // Channel untuk mengirim hasil
	resolvers []string, // Daftar resolver DNS yang digunakan
	cache *models.DNSCache, // Cache untuk menghindari pencarian duplikat
	client *http.Client, // HTTP client untuk deteksi takeover
	bar *pb.ProgressBar, // Progress bar untuk umpan balik visual
	resultWriter *output.ResultWriter, // Writer untuk tampilan hasil real-time
	wg *sync.WaitGroup, // WaitGroup untuk sinkronisasi
	showIP bool, // Apakah menyertakan alamat IP dalam hasil
	rateLimit int, // Rate limiting dalam milidetik antara permintaan
	streamOutput chan<- models.SubdomainResult, // Channel untuk streaming hasil
) {
	defer wg.Done()

	for subdomain := range subdomainChan {
		var result models.SubdomainResult

		// Cek cache dulu
		if cachedResult, ok := cache.Load(subdomain); ok {
			// Gunakan hasil DNS cache jika tersedia
			if cachedResult.Found {
				result = models.SubdomainResult{Subdomain: subdomain, IPs: cachedResult.IPs}
				if client != nil {
					// Periksa potensi takeover
					CheckTakeover(client, &result)
				}
				resultChan <- result

				// Tulis hasil secara real-time
				if resultWriter != nil {
					resultWriter.WriteResult(result)
				}

				if streamOutput != nil {
					streamOutput <- result
				}
			}
		} else {
			var addresses []string
			var err error
			if len(resolvers) > 0 {
				// Coba setiap resolver sampai satu berhasil
				for _, resolver := range resolvers {
					addresses, err = utils.LookupWithResolver(subdomain, resolver)
					if err == nil {
						break
					}
				}
			} else {
				// Gunakan resolver default sistem
				addresses, err = utils.DefaultLookup(subdomain)
			}

			if err == nil {
				// Subdomain ada
				cache.Store(subdomain, models.DNSResult{Found: true, IPs: addresses})
				result = models.SubdomainResult{Subdomain: subdomain}
				if showIP {
					result.IPs = addresses
				}
				if client != nil {
					// Periksa potensi takeover
					CheckTakeover(client, &result)
				}
				resultChan <- result

				// Tulis hasil secara real-time
				if resultWriter != nil {
					resultWriter.WriteResult(result)
				}

				if streamOutput != nil {
					streamOutput <- result
				}
			} else {
				// Subdomain tidak ada
				cache.Store(subdomain, models.DNSResult{Found: false})
			}
		}

		// Update progress bar
		bar.Increment()

		// Rate limiter
		if rateLimit > 0 {
			time.Sleep(time.Duration(rateLimit) * time.Millisecond)
		}
	}
}
