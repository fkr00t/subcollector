package scanner

import (
	"github.com/fkr00t/subcollector/internal/models"
	"io"
	"time"
)

// BackoffConfig konfigurasi untuk algoritma backoff
type BackoffConfig struct {
	Enabled       bool
	BaseDelay     time.Duration
	MaxDelay      time.Duration
	Factor        float64
	Jitter        float64
	FailThreshold int
}

// StreamingActiveScanConfig konfigurasi untuk pemindaian aktif dengan streaming
// StreamingActiveScanConfig konfigurasi untuk pemindaian aktif dengan streaming
type StreamingActiveScanConfig struct {
	Domain          string
	WordlistPath    string
	WordlistReader  io.Reader // Ubah dari interface{} menjadi io.Reader
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
