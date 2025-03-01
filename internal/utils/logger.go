package utils

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// LogLevel menentukan tingkat level log
type LogLevel int

const (
	LevelDebug LogLevel = iota
	LevelInfo
	LevelWarning
	LevelError
	LevelFatal
)

// LoggerConfig adalah konfigurasi untuk Logger
type LoggerConfig struct {
	Level        LogLevel  // Minimal log level
	OutputFile   string    // Path ke file output (opsional)
	ColorEnabled bool      // Apakah warna diaktifkan
	TimeFormat   string    // Format timestamp
	Writer       io.Writer // Writer kustom (opsional, default: os.Stdout)
}

// Logger adalah logger terstruktur thread-safe
type Logger struct {
	config LoggerConfig
	mu     sync.Mutex
	file   *os.File
	writer io.Writer
}

// String representation dari log level
func (l LogLevel) String() string {
	switch l {
	case LevelDebug:
		return "DEBUG"
	case LevelInfo:
		return "INFO"
	case LevelWarning:
		return "WARN"
	case LevelError:
		return "ERROR"
	case LevelFatal:
		return "FATAL"
	default:
		return "UNKNOWN"
	}
}

// Color codes untuk log level
func (l LogLevel) Color() string {
	switch l {
	case LevelDebug:
		return "\033[36m" // Cyan
	case LevelInfo:
		return "\033[32m" // Green
	case LevelWarning:
		return "\033[33m" // Yellow
	case LevelError:
		return "\033[31m" // Red
	case LevelFatal:
		return "\033[35m" // Magenta
	default:
		return "\033[0m" // Reset
	}
}

// NewLogger membuat instance logger baru
func NewLogger(config LoggerConfig) (*Logger, error) {
	logger := &Logger{
		config: config,
		writer: os.Stdout,
	}

	// Gunakan writer kustom jika disediakan
	if config.Writer != nil {
		logger.writer = config.Writer
	}

	// Buka file output jika disediakan
	if config.OutputFile != "" {
		file, err := os.OpenFile(config.OutputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return nil, fmt.Errorf("gagal membuka file log: %v", err)
		}
		logger.file = file

		// Jika tidak ada writer kustom, gunakan file sebagai writer
		if config.Writer == nil {
			logger.writer = file
		}
	}

	// Set format timestamp default jika tidak disediakan
	if config.TimeFormat == "" {
		logger.config.TimeFormat = "2006-01-02 15:04:05"
	}

	return logger, nil
}

// Close menutup logger dan file terkait
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.file != nil {
		return l.file.Close()
	}
	return nil
}

// formatMessage memformat pesan log dengan level, timestamp, dan warna
func (l *Logger) formatMessage(level LogLevel, message string) string {
	timestamp := time.Now().Format(l.config.TimeFormat)
	levelStr := level.String()

	// Format dasar: [LEVEL] [TIME] message
	formatted := fmt.Sprintf("[%s] [%s] %s", levelStr, timestamp, message)

	// Tambahkan warna jika diaktifkan
	if l.config.ColorEnabled && l.writer == os.Stdout {
		colorCode := level.Color()
		resetCode := "\033[0m"
		formatted = fmt.Sprintf("%s%s%s", colorCode, formatted, resetCode)
	}

	return formatted
}

// log adalah metode internal untuk menulis pesan log
func (l *Logger) log(level LogLevel, message string, args ...interface{}) {
	// Skip jika level lebih rendah dari konfigurasi
	if level < l.config.Level {
		return
	}

	// Format pesan jika args disediakan
	if len(args) > 0 {
		message = fmt.Sprintf(message, args...)
	}

	// Format pesan log
	formatted := l.formatMessage(level, message)

	// Tambahkan newline jika belum ada
	if !strings.HasSuffix(formatted, "\n") {
		formatted += "\n"
	}

	// Tulis log ke output dengan mutex untuk thread safety
	l.mu.Lock()
	defer l.mu.Unlock()

	fmt.Fprint(l.writer, formatted)

	// Jika kita memiliki file dan writer kustom, tulis juga ke file
	if l.file != nil && l.writer != l.file {
		// Format tanpa warna untuk file
		plainFormatted := l.formatMessage(level, message)
		if !strings.HasSuffix(plainFormatted, "\n") {
			plainFormatted += "\n"
		}
		fmt.Fprint(l.file, plainFormatted)
	}

	// Keluar jika fatal
	if level == LevelFatal {
		os.Exit(1)
	}
}

// Debug logs message dengan level Debug
func (l *Logger) Debug(message string, args ...interface{}) {
	l.log(LevelDebug, message, args...)
}

// Info logs message dengan level Info
func (l *Logger) Info(message string, args ...interface{}) {
	l.log(LevelInfo, message, args...)
}

// Warn logs message dengan level Warning
func (l *Logger) Warn(message string, args ...interface{}) {
	l.log(LevelWarning, message, args...)
}

// Error logs message dengan level Error
func (l *Logger) Error(message string, args ...interface{}) {
	l.log(LevelError, message, args...)
}

// Fatal logs message dengan level Fatal dan exit(1)
func (l *Logger) Fatal(message string, args ...interface{}) {
	l.log(LevelFatal, message, args...)
}

// Singleton global logger untuk kemudahan penggunaan
var (
	globalLogger *Logger
	once         sync.Once
)

// InitGlobalLogger menginisialisasi logger global
func InitGlobalLogger(config LoggerConfig) error {
	var err error
	once.Do(func() {
		globalLogger, err = NewLogger(config)
	})
	return err
}

// GetLogger mengembalikan instance logger global
func GetLogger() *Logger {
	if globalLogger == nil {
		// Inisialisasi logger default jika belum diinisialisasi
		_ = InitGlobalLogger(LoggerConfig{
			Level:        LevelInfo,
			ColorEnabled: true,
		})
	}
	return globalLogger
}

// Helper functions untuk menggunakan logger global secara langsung

// Debug logs message dengan level Debug menggunakan logger global
func Debug(message string, args ...interface{}) {
	GetLogger().Debug(message, args...)
}

// Info logs message dengan level Info menggunakan logger global
func Info(message string, args ...interface{}) {
	GetLogger().Info(message, args...)
}

// Warn logs message dengan level Warning menggunakan logger global
func Warn(message string, args ...interface{}) {
	GetLogger().Warn(message, args...)
}

// Error logs message dengan level Error menggunakan logger global
func Error(message string, args ...interface{}) {
	GetLogger().Error(message, args...)
}

// Fatal logs message dengan level Fatal menggunakan logger global dan exit(1)
func Fatal(message string, args ...interface{}) {
	GetLogger().Fatal(message, args...)
}
