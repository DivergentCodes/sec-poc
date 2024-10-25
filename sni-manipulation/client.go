package main

import (
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

const (
	SNI_VALUE = "npmjs.com"
)

func main() {
	// Create a custom TLS configuration
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,      // Skip certificate verification (for testing only)
		ServerName:         SNI_VALUE, // Set the SNI value
	}

	// Create a custom transport with our TLS configuration
	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	// Create a client with our custom transport
	client := &http.Client{Transport: transport}

	// Make the HTTPS request
	resp, err := client.Get("https://localhost:8443")
	if err != nil {
		log.Fatal("Error making request:", err)
	}
	defer resp.Body.Close()

	// Read and print the response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal("Error reading response:", err)
	}

	fmt.Printf("Response from server: %s\n", body)
}
