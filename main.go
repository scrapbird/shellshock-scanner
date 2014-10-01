package main

import (
	"flag"
	"fmt"
	"os"
	"bufio"
)

var nworkers int
var infile string
var outfile string

func main () {
	flag.IntVar(&nworkers, "workers", 20, "The number of worker threads to spawn")
	flag.StringVar(&infile, "in", "urls.txt", "File with list of urls to check for vulnerability")
	flag.StringVar(&outfile, "out", "out.txt", "File to dump all vulnerable urls into")
	flag.Parse()

	// create the worker queue
	workerQueue := make(chan chan WorkRequest, nworkers)

	// create the workers
	fmt.Printf("Starting %d workers\n", nworkers)
	workers := make([]Worker, nworkers)
	for i := range workers {
		workers[i] = NewWorker(i, workerQueue)
		workers[i].Start()
	}

	// open input file
    f, err := os.Open(infile)
    if err != nil {
        panic(err)
    }
    // close file on exit and check for its returned error
    defer func() {
        if err := f.Close(); err != nil {
            panic(err)
        }
    }()

	// create scanner
	scanner := bufio.NewScanner(f)

	// read until end of file and submit urls to workers
	for scanner.Scan() {
		// create a new work request and send it to a worker
		workRequest := WorkRequest{Url: scanner.Text()}
		worker := <-workerQueue
		worker <- workRequest
	}
	if err := scanner.Err(); err != nil {
		panic(err)
	}

	// inform workers that all work has been sent out and they should quite
	fmt.Println("Sending stop request to all workers")
	for i := range workers {
		workers[i].Stop()
	}
	// wait for all workers to finish
	for i := range workers {
		<-workers[i].Done
	}

	fmt.Println("All work is complete")
}

