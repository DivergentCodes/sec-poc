package main

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

func main() {
	// Create a custom HTTP client with TLS configuration
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // Skip certificate verification
		},
	}
	client := &http.Client{Transport: tr}

	// Make the HTTPS request
	resp, err := client.Get("https://localhost:8443")
	if err != nil {
		log.Fatal("Error making request:", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal("Error reading response:", err)
	}

	fmt.Println("Server response:", string(body))
}
