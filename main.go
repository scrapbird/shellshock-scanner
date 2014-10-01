package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
)

var nworkers int
var infile string
var outfile string

func main() {
	flag.IntVar(&nworkers, "workers", 1, "The number of worker threads to spawn")
	flag.StringVar(&infile, "in", "", "File with list of urls to check for vulnerability")
	flag.StringVar(&outfile, "out", "", "File to dump all vulnerable urls into")
	flag.Parse()

	// check flags
	if nworkers < 0 {
		fmt.Println("Must have at least one worker")
		return
	}
	if infile == "" {
		fmt.Println("Must speicify a file to read urls from")
		return
	}
	if outfile == "" {
		fmt.Println("Must specify a file to dump vulnerable links into")
		return
	}

	// open input file
	inf, err := os.Open(infile)
	if err != nil {
		fmt.Printf("Failed to open file: %s\n", infile)
		return
	}
	// close file on exit and check if it returned an error
	defer func() {
		if err := inf.Close(); err != nil {
			fmt.Println("Warning: could not safely close file containing urls")
		}
	}()

	// open output file
	outf, err := os.OpenFile(outfile, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		fmt.Println("Failed to open output file for writing")
		return
	}
	// close file on exit and check if it returned an error
	defer func() {
		if err := outf.Close(); err != nil {
			fmt.Println("Warning: could not safely close output file")
		}
	}()

	// create the worker queue
	workerQueue := make(chan chan WorkRequest, nworkers)

	// create the channel that vulnerable urls are sent to
	vulnerableUrls := make(chan string)
	// listen for vulnerable urls being send on this channel
	go func() {
		for {
			url := <-vulnerableUrls
			fmt.Printf("Found a vulnerable url: %s\n", url)
			output := url + "\n"
			_, err := outf.WriteString(output)
			if err != nil {
				panic(err)
			}
		}
	}()

	// create the workers
	fmt.Printf("Starting %d workers\n", nworkers)
	workers := make([]Worker, nworkers)
	for i := range workers {
		workers[i] = NewWorker(i, workerQueue, vulnerableUrls)
		workers[i].Start()
	}

	// create scanner
	scanner := bufio.NewScanner(inf)

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

	// inform workers that all work has been sent out and they should quit
	for i := range workers {
		workers[i].Stop()
	}
	// wait for all workers to finish
	for i := range workers {
		<-workers[i].Done
	}

	fmt.Println("All work is complete")
}
