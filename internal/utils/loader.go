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

// LoadDomains membaca daftar domain dari file
// Setiap domain harus berada pada baris baru
// Mengembalikan slice domain dan error yang ditemui
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

// LoadWordlist membaca wordlist dari file untuk pemindaian aktif
// Setiap kata harus berada pada baris baru
// Mengembalikan slice kata dan error yang ditemui
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

// FetchWordlistFromURL mengunduh wordlist dari URL
// Digunakan ketika tidak ada wordlist lokal yang ditentukan
// Mengembalikan slice kata dan error yang ditemui
func FetchWordlistFromURL(url string) ([]string, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("gagal mengunduh wordlist: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gagal mengunduh wordlist: kode status %d", resp.StatusCode)
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
		return nil, fmt.Errorf("gagal membaca wordlist: %v", err)
	}

	return wordlist, nil
}

// FetchWordlistReaderFromURL mengunduh wordlist dari URL dan mengembalikan reader
// untuk streaming yang lebih efisien
func FetchWordlistReaderFromURL(url string) (io.Reader, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("gagal mengunduh wordlist: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("gagal mengunduh wordlist: kode status %d", resp.StatusCode)
	}

	return resp.Body, nil
}

// LoadWordlistReader membaca wordlist dari file dan mengembalikan reader
// untuk streaming yang lebih efisien
func LoadWordlistReader(filePath string) (io.Reader, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	return file, nil
}

// LoadResolvers membaca daftar resolver DNS dari file
// Setiap resolver harus berada pada baris baru
// Baris yang dimulai dengan # diperlakukan sebagai komentar
// Mengembalikan slice alamat resolver dan error yang ditemui
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

// CountLinesInFile menghitung jumlah baris dalam file
// Metode ini lebih efisien daripada membaca seluruh file ke memori
func CountLinesInFile(filePath string) (int, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	// Buat buffer untuk membaca secara efisien
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

		// Hitung jumlah newline dalam buffer
		count += bytes.Count(buf[:c], lineSep)
	}

	// Jika file tidak diakhiri dengan newline, tambahkan satu baris
	if count > 0 {
		// Periksa karakter terakhir
		_, err := file.Seek(-1, io.SeekEnd)
		if err != nil {
			return count, nil // Abaikan error, gunakan jumlah yang dihitung
		}

		lastChar := make([]byte, 1)
		_, err = file.Read(lastChar)
		if err != nil {
			return count, nil // Abaikan error, gunakan jumlah yang dihitung
		}

		if lastChar[0] != '\n' {
			count++
		}
	}

	return count, nil
}
