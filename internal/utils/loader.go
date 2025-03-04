package utils

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

// LoadDomains reads a list of domains from a file
// Each domain should be on a new line
// Returns a slice of domains and any errors encountered
func LoadDomains(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var domains []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		domain := strings.TrimSpace(scanner.Text())
		if domain != "" {
			domains = append(domains, domain)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return domains, nil
}

// LoadWordlist reads a wordlist from a file for active scanning
// Each word should be on a new line
// Returns a slice of words and any errors encountered
func LoadWordlist(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var wordlist []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if word != "" {
			wordlist = append(wordlist, word)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return wordlist, nil
}

// FetchWordlistFromURL downloads a wordlist from a URL
// Used when no local wordlist is specified
// Returns a slice of words and any errors encountered
func FetchWordlistFromURL(url string) ([]string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to download wordlist: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to download wordlist: status code %d", resp.StatusCode)
	}

	var wordlist []string
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		word := strings.TrimSpace(scanner.Text())
		if word != "" {
			wordlist = append(wordlist, word)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read wordlist: %v", err)
	}

	return wordlist, nil
}

// FetchWordlistReaderFromURL downloads a wordlist from a URL and returns a reader
// for more efficient streaming
func FetchWordlistReaderFromURL(url string) (io.Reader, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to download wordlist: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("failed to download wordlist: status code %d", resp.StatusCode)
	}

	return resp.Body, nil
}

// LoadWordlistReader reads a wordlist from a file and returns a reader
// for more efficient streaming
func LoadWordlistReader(filePath string) (io.Reader, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	return file, nil
}

// LoadResolvers reads a list of DNS resolvers from a file
// Each resolver should be on a new line
// Lines starting with # are treated as comments
// Returns a slice of resolver addresses and any errors encountered
func LoadResolvers(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var resolvers []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		resolver := strings.TrimSpace(scanner.Text())
		if resolver != "" && !strings.HasPrefix(resolver, "#") {
			resolvers = append(resolvers, resolver)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return resolvers, nil
}

// CountLinesInFile counts the number of lines in a file
// This method is more efficient than reading the entire file into memory
func CountLinesInFile(filePath string) (int, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	// Create buffer for efficient reading
	buf := make([]byte, 32*1024)
	count := 0
	lineSep := []byte{'\n'}

	for {
		c, err := file.Read(buf)
		if err != nil && err != io.EOF {
			return count, err
		}

		if c == 0 {
			break
		}

		// Count the number of newlines in the buffer
		count += bytes.Count(buf[:c], lineSep)
	}

	// If the file doesn't end with a newline, add one line
	if count > 0 {
		// Check the last character
		_, err := file.Seek(-1, io.SeekEnd)
		if err != nil {
			return count, nil // Ignore error, use the counted amount
		}

		lastChar := make([]byte, 1)
		_, err = file.Read(lastChar)
		if err != nil {
			return count, nil // Ignore error, use the counted amount
		}

		if lastChar[0] != '\n' {
			count++
		}
	}

	return count, nil
}
