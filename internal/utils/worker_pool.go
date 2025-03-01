package utils

import (
	"context"
	"sync"
)

// WorkerTask mewakili pekerjaan yang akan dilakukan.
type WorkerTask func() interface{}

// WorkerPool mengimplementasikan sebuah pool worker yang dapat digunakan kembali.
type WorkerPool struct {
	tasksChan     chan WorkerTask
	resultsChan   chan interface{}
	numWorkers    int
	wg            sync.WaitGroup
	ctx           context.Context
	cancel        context.CancelFunc
	isInitialized bool
}

// NewWorkerPool membuat instance baru WorkerPool dengan jumlah worker yang ditentukan.
func NewWorkerPool(numWorkers int, bufferSize int) *WorkerPool {
	ctx, cancel := context.WithCancel(context.Background())
	return &WorkerPool{
		tasksChan:   make(chan WorkerTask, bufferSize),
		resultsChan: make(chan interface{}, bufferSize),
		numWorkers:  numWorkers,
		ctx:         ctx,
		cancel:      cancel,
	}
}

// Start memulai worker pool.
func (wp *WorkerPool) Start() {
	if wp.isInitialized {
		return
	}

	for i := 0; i < wp.numWorkers; i++ {
		wp.wg.Add(1)
		go wp.worker()
	}
	wp.isInitialized = true
}

// worker adalah goroutine yang menangani tasks.
func (wp *WorkerPool) worker() {
	defer wp.wg.Done()

	for {
		select {
		case <-wp.ctx.Done():
			return
		case task, ok := <-wp.tasksChan:
			if !ok {
				return
			}
			result := task()
			if result != nil {
				select {
				case wp.resultsChan <- result:
				case <-wp.ctx.Done():
					return
				}
			}
		}
	}
}

// AddTask menambahkan task ke worker pool.
func (wp *WorkerPool) AddTask(task WorkerTask) {
	select {
	case <-wp.ctx.Done():
		return
	case wp.tasksChan <- task:
	}
}

// Results mengembalikan channel yang menerima hasil.
func (wp *WorkerPool) Results() <-chan interface{} {
	return wp.resultsChan
}

// Stop menghentikan worker pool dan menunggu sampai semua worker selesai.
func (wp *WorkerPool) Stop() {
	wp.cancel() // Signal workers to stop
	close(wp.tasksChan)
	wp.wg.Wait() // Wait for all workers to exit
	close(wp.resultsChan)
	wp.isInitialized = false
}

// StopAndDrain menghentikan worker pool, menunggu sampai semua workers selesai,
// dan mengembalikan semua hasil yang belum dikonsumsi.
func (wp *WorkerPool) StopAndDrain() []interface{} {
	wp.Stop()

	var results []interface{}
	for result := range wp.resultsChan {
		results = append(results, result)
	}
	return results
}
