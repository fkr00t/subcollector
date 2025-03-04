package utils

import (
	"context"
	"sync"
)

// WorkerTask represents a job to be performed.
type WorkerTask func() interface{}

// WorkerPool implements a reusable worker pool.
type WorkerPool struct {
	tasksChan     chan WorkerTask
	resultsChan   chan interface{}
	numWorkers    int
	wg            sync.WaitGroup
	ctx           context.Context
	cancel        context.CancelFunc
	isInitialized bool
}

// NewWorkerPool creates a new WorkerPool instance with the specified number of workers.
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

// Start initiates the worker pool.
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

// worker is a goroutine that handles tasks.
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

// AddTask adds a task to the worker pool.
func (wp *WorkerPool) AddTask(task WorkerTask) {
	select {
	case <-wp.ctx.Done():
		return
	case wp.tasksChan <- task:
	}
}

// Results returns a channel that receives results.
func (wp *WorkerPool) Results() <-chan interface{} {
	return wp.resultsChan
}

// Stop stops the worker pool and waits until all workers are done.
func (wp *WorkerPool) Stop() {
	wp.cancel() // Signal workers to stop
	close(wp.tasksChan)
	wp.wg.Wait() // Wait for all workers to exit
	close(wp.resultsChan)
	wp.isInitialized = false
}

// StopAndDrain stops the worker pool, waits until all workers are done,
// and returns all unconsumed results.
func (wp *WorkerPool) StopAndDrain() []interface{} {
	wp.Stop()

	var results []interface{}
	for result := range wp.resultsChan {
		results = append(results, result)
	}
	return results
}
