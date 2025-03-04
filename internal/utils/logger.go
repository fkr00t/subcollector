package utils

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// LogLevel determines the log level
type LogLevel int

const (
	LevelDebug LogLevel = iota
	LevelInfo
	LevelWarning
	LevelError
	LevelFatal
)

// LoggerConfig is the configuration for Logger
type LoggerConfig struct {
	Level        LogLevel  // Minimum log level
	OutputFile   string    // Path to output file (optional)
	ColorEnabled bool      // Whether color is enabled
	TimeFormat   string    // Timestamp format
	Writer       io.Writer // Custom writer (optional, default: os.Stdout)
}

// Logger is a thread-safe structured logger
type Logger struct {
	config LoggerConfig
	mu     sync.Mutex
	file   *os.File
	writer io.Writer
}

// String representation of log level
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

// Color codes for log level
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

// NewLogger creates a new logger instance
func NewLogger(config LoggerConfig) (*Logger, error) {
	logger := &Logger{
		config: config,
		writer: os.Stdout,
	}

	// Use custom writer if provided
	if config.Writer != nil {
		logger.writer = config.Writer
	}

	// Open output file if provided
	if config.OutputFile != "" {
		file, err := os.OpenFile(config.OutputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return nil, fmt.Errorf("failed to open log file: %v", err)
		}
		logger.file = file

		// If no custom writer, use file as writer
		if config.Writer == nil {
			logger.writer = file
		}
	}

	// Set default timestamp format if not provided
	if config.TimeFormat == "" {
		logger.config.TimeFormat = "2006-01-02 15:04:05"
	}

	return logger, nil
}

// Close closes the logger and related file
func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.file != nil {
		return l.file.Close()
	}
	return nil
}

// formatMessage formats a log message with level, timestamp, and color
func (l *Logger) formatMessage(level LogLevel, message string) string {
	timestamp := time.Now().Format(l.config.TimeFormat)
	levelStr := level.String()

	// Basic format: [LEVEL] [TIME] message
	formatted := fmt.Sprintf("[%s] [%s] %s", levelStr, timestamp, message)

	// Add color if enabled
	if l.config.ColorEnabled && l.writer == os.Stdout {
		colorCode := level.Color()
		resetCode := "\033[0m"
		formatted = fmt.Sprintf("%s%s%s", colorCode, formatted, resetCode)
	}

	return formatted
}

// log is an internal method for writing log messages
func (l *Logger) log(level LogLevel, message string, args ...interface{}) {
	// Skip if level is lower than configuration
	if level < l.config.Level {
		return
	}

	// Format message if args provided
	if len(args) > 0 {
		message = fmt.Sprintf(message, args...)
	}

	// Format log message
	formatted := l.formatMessage(level, message)

	// Add newline if not already there
	if !strings.HasSuffix(formatted, "\n") {
		formatted += "\n"
	}

	// Write log to output with mutex for thread safety
	l.mu.Lock()
	defer l.mu.Unlock()

	fmt.Fprint(l.writer, formatted)

	// If we have a file and custom writer, also write to file
	if l.file != nil && l.writer != l.file {
		// Format without color for file
		plainFormatted := l.formatMessage(level, message)
		if !strings.HasSuffix(plainFormatted, "\n") {
			plainFormatted += "\n"
		}
		fmt.Fprint(l.file, plainFormatted)
	}

	// Exit if fatal
	if level == LevelFatal {
		os.Exit(1)
	}
}

// Debug logs a message with Debug level
func (l *Logger) Debug(message string, args ...interface{}) {
	l.log(LevelDebug, message, args...)
}

// Info logs a message with Info level
func (l *Logger) Info(message string, args ...interface{}) {
	l.log(LevelInfo, message, args...)
}

// Warn logs a message with Warning level
func (l *Logger) Warn(message string, args ...interface{}) {
	l.log(LevelWarning, message, args...)
}

// Error logs a message with Error level
func (l *Logger) Error(message string, args ...interface{}) {
	l.log(LevelError, message, args...)
}

// Fatal logs a message with Fatal level and exit(1)
func (l *Logger) Fatal(message string, args ...interface{}) {
	l.log(LevelFatal, message, args...)
}

// Singleton global logger for ease of use
var (
	globalLogger *Logger
	once         sync.Once
)

// InitGlobalLogger initializes the global logger
func InitGlobalLogger(config LoggerConfig) error {
	var err error
	once.Do(func() {
		globalLogger, err = NewLogger(config)
	})
	return err
}

// GetLogger returns the global logger instance
func GetLogger() *Logger {
	if globalLogger == nil {
		// Initialize default logger if not initialized
		_ = InitGlobalLogger(LoggerConfig{
			Level:        LevelInfo,
			ColorEnabled: true,
		})
	}
	return globalLogger
}

// Helper functions for using the global logger directly

// Debug logs a message with Debug level using the global logger
func Debug(message string, args ...interface{}) {
	GetLogger().Debug(message, args...)
}

// Info logs a message with Info level using the global logger
func Info(message string, args ...interface{}) {
	GetLogger().Info(message, args...)
}

// Warn logs a message with Warning level using the global logger
func Warn(message string, args ...interface{}) {
	GetLogger().Warn(message, args...)
}

// Error logs a message with Error level using the global logger
func Error(message string, args ...interface{}) {
	GetLogger().Error(message, args...)
}

// Fatal logs a message with Fatal level using the global logger and exit(1)
func Fatal(message string, args ...interface{}) {
	GetLogger().Fatal(message, args...)
}
