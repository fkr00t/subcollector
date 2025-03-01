package utils

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"sync"
)

// ChunkProcessor menangani pemrosesan data dalam chunk untuk penggunaan memori yang efisien
type ChunkProcessor struct {
	chunkSize     int
	numWorkers    int
	maxQueueSize  int
	processor     func([]string) error
	errorCallback func(error)
}

// NewChunkProcessor membuat instance baru dari ChunkProcessor
func NewChunkProcessor(chunkSize, numWorkers, maxQueueSize int, processor func([]string) error, errorCallback func(error)) *ChunkProcessor {
	return &ChunkProcessor{
		chunkSize:     chunkSize,
		numWorkers:    numWorkers,
		maxQueueSize:  maxQueueSize,
		processor:     processor,
		errorCallback: errorCallback,
	}
}

// ProcessReader memproses data dari reader dalam chunk
func (cp *ChunkProcessor) ProcessReader(reader io.Reader) error {
	scanner := bufio.NewScanner(reader)

	// Buat buffer untuk memuat chunk sementara
	chunks := make(chan []string, cp.maxQueueSize)

	// Goroutine untuk membaca data dan membuat chunk
	go func() {
		defer close(chunks)

		currentChunk := make([]string, 0, cp.chunkSize)

		for scanner.Scan() {
			line := scanner.Text()
			if line != "" {
				currentChunk = append(currentChunk, line)

				// Jika chunk sudah penuh, kirim ke channel
				if len(currentChunk) >= cp.chunkSize {
					// Buat salinan chunk untuk dikirim (karena slice bersifat referensi)
					chunkCopy := make([]string, len(currentChunk))
					copy(chunkCopy, currentChunk)
					chunks <- chunkCopy

					// Reset chunk
					currentChunk = make([]string, 0, cp.chunkSize)
				}
			}
		}

		// Kirim chunk terakhir jika ada
		if len(currentChunk) > 0 {
			chunks <- currentChunk
		}

		// Periksa error scanner
		if err := scanner.Err(); err != nil {
			if cp.errorCallback != nil {
				cp.errorCallback(fmt.Errorf("error saat membaca data: %v", err))
			}
		}
	}()

	// Buat worker pool untuk memproses chunk
	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < cp.numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			for chunk := range chunks {
				if err := cp.processor(chunk); err != nil {
					if cp.errorCallback != nil {
						cp.errorCallback(err)
					}
				}
			}
		}()
	}

	// Tunggu semua worker selesai
	wg.Wait()

	return nil
}

// ProcessWordlist memproses file wordlist dalam chunk
func (cp *ChunkProcessor) ProcessWordlist(filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("gagal membuka file wordlist: %v", err)
	}
	defer file.Close()

	return cp.ProcessReader(file)
}

// ProcessStringSlice memproses slice string dalam chunk
func (cp *ChunkProcessor) ProcessStringSlice(items []string) error {
	itemsCopy := make([]string, len(items))
	copy(itemsCopy, items)

	// Buat channel untuk chunk
	chunks := make(chan []string, cp.maxQueueSize)

	// Goroutine untuk membagi slice menjadi chunk
	go func() {
		defer close(chunks)

		for i := 0; i < len(itemsCopy); i += cp.chunkSize {
			end := i + cp.chunkSize
			if end > len(itemsCopy) {
				end = len(itemsCopy)
			}

			// Buat chunk baru dari slice
			chunk := itemsCopy[i:end]
			chunks <- chunk
		}
	}()

	// Buat worker pool untuk memproses chunk
	var wg sync.WaitGroup

	// Start workers
	for i := 0; i < cp.numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			for chunk := range chunks {
				if err := cp.processor(chunk); err != nil {
					if cp.errorCallback != nil {
						cp.errorCallback(err)
					}
				}
			}
		}()
	}

	// Tunggu semua worker selesai
	wg.Wait()

	return nil
}
