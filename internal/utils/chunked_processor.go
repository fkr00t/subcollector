package utils

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"sync"
)

// ChunkProcessor handles data processing in chunks for efficient memory usage
type ChunkProcessor struct {
	chunkSize     int
	numWorkers    int
	maxQueueSize  int
	processor     func([]string) error
	errorCallback func(error)
}

// NewChunkProcessor creates a new instance of ChunkProcessor
func NewChunkProcessor(chunkSize, numWorkers, maxQueueSize int, processor func([]string) error, errorCallback func(error)) *ChunkProcessor {
	return &ChunkProcessor{
		chunkSize:     chunkSize,
		numWorkers:    numWorkers,
		maxQueueSize:  maxQueueSize,
		processor:     processor,
		errorCallback: errorCallback,
	}
}

// ProcessReader processes data from reader in chunks
func (cp *ChunkProcessor) ProcessReader(reader io.Reader) error {
	scanner := bufio.NewScanner(reader)

	// Create buffer to hold temporary chunks
	chunks := make(chan []string, cp.maxQueueSize)

	// Goroutine to read data and create chunks
	go func() {
		defer close(chunks)

		currentChunk := make([]string, 0, cp.chunkSize)

		for scanner.Scan() {
			line := scanner.Text()
			if line != "" {
				currentChunk = append(currentChunk, line)

				// If chunk is full, send to channel
				if len(currentChunk) >= cp.chunkSize {
					// Create a copy of the chunk to send (since slices are references)
					chunkCopy := make([]string, len(currentChunk))
					copy(chunkCopy, currentChunk)
					chunks <- chunkCopy

					// Reset chunk
					currentChunk = make([]string, 0, cp.chunkSize)
				}
			}
		}

		// Send last chunk if it exists
		if len(currentChunk) > 0 {
			chunks <- currentChunk
		}

		// Check scanner errors
		if err := scanner.Err(); err != nil {
			if cp.errorCallback != nil {
				cp.errorCallback(fmt.Errorf("error while reading data: %v", err))
			}
		}
	}()

	// Create worker pool to process chunks
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

	// Wait for all workers to finish
	wg.Wait()

	return nil
}

// ProcessWordlist processes a wordlist file in chunks
func (cp *ChunkProcessor) ProcessWordlist(filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return fmt.Errorf("failed to open wordlist file: %v", err)
	}
	defer file.Close()

	return cp.ProcessReader(file)
}

// ProcessStringSlice processes a string slice in chunks
func (cp *ChunkProcessor) ProcessStringSlice(items []string) error {
	itemsCopy := make([]string, len(items))
	copy(itemsCopy, items)

	// Create channel for chunks
	chunks := make(chan []string, cp.maxQueueSize)

	// Goroutine to divide slice into chunks
	go func() {
		defer close(chunks)

		for i := 0; i < len(itemsCopy); i += cp.chunkSize {
			end := i + cp.chunkSize
			if end > len(itemsCopy) {
				end = len(itemsCopy)
			}

			// Create new chunk from slice
			chunk := itemsCopy[i:end]
			chunks <- chunk
		}
	}()

	// Create worker pool to process chunks
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

	// Wait for all workers to finish
	wg.Wait()

	return nil
}
