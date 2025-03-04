package scanner

import (
	"github.com/fkr00t/subcollector/internal/models"
	"io"
	"time"
)

// BackoffConfig configuration for the backoff algorithm
type BackoffConfig struct {
	Enabled       bool
	BaseDelay     time.Duration
	MaxDelay      time.Duration
	Factor        float64
	Jitter        float64
	FailThreshold int
}

// StreamingActiveScanConfig configuration for active scanning with streaming
// StreamingActiveScanConfig configuration for active scanning with streaming
type StreamingActiveScanConfig struct {
	Domain          string
	WordlistPath    string
	WordlistReader  io.Reader // Changed from interface{} to io.Reader
	Resolvers       []string
	BackoffConfig   BackoffConfig
	Recursive       bool
	ShowIP          bool
	Depth           int
	Takeover        bool
	Proxy           string
	NumWorkers      int
	ChunkSize       int
	ResultProcessor func(models.SubdomainResult)
}
