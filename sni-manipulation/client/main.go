package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
)

func main() {
	var targetIP string
	var targetPort string
	var sniValue string

	if len(os.Args) != 4 {
		fmt.Println("Usage: ./client <target_ip> <target_port> <sni_value>")
		os.Exit(1)
	}

	targetIP = os.Args[1]
	targetPort = os.Args[2]
	sniValue = os.Args[3]

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         sniValue,
	}

	// Create a custom dialer
	dialer := &tls.Dialer{
		Config: tlsConfig,
	}

	// Create a custom transport with our dialer
	transport := &http.Transport{
		DialTLS: func(network, addr string) (net.Conn, error) {
			conn, err := dialer.Dial(network, addr)
			if err != nil {
				return nil, err
			}
			// Type assert to *tls.Conn to access ConnectionState
			tlsConn := conn.(*tls.Conn)
			// Handshake is required to populate ConnectionState
			if err := tlsConn.Handshake(); err != nil {
				conn.Close()
				return nil, err
			}
			fmt.Printf("Sending request...\n\tIP: %s\n\tSNI:  %s\n", targetIP, tlsConn.ConnectionState().ServerName)
			return conn, nil
		},
	}

	// Create a client with our custom transport
	client := &http.Client{Transport: transport}

	// Make the HTTPS request
	resp, err := client.Get(fmt.Sprintf("https://%s:%s", targetIP, targetPort))
	if err != nil {
		log.Fatal("Error making request:", err)
	}
	defer resp.Body.Close()

	// Read and print the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatal("Error reading response:", err)
	}

	fmt.Printf("Response: [%s]\n", body)
}
