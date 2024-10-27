package main

import (
	"crypto/tls"
	"embed"
	"fmt"
	"log"
	"net/http"
	"os"
)

//go:embed certs/server.crt certs/server.key
var certsFS embed.FS

func main() {
	var host string
	var port string

	if len(os.Args) != 3 {
		fmt.Println("Usage: ./server <host> <port>")
		os.Exit(1)
	}

	host = os.Args[1]
	port = os.Args[2]

	addr := fmt.Sprintf("%s:%s", host, port)
	certPEMBytes, err := certsFS.ReadFile("certs/server.crt")
	if err != nil {
		log.Fatal(err)
	}
	keyPEMBytes, err := certsFS.ReadFile("certs/server.key")
	if err != nil {
		log.Fatal(err)
	}

	cert, err := tls.X509KeyPair(certPEMBytes, keyPEMBytes)
	if err != nil {
		log.Fatal(err)
	}

	server := &http.Server{
		Addr:    addr,
		Handler: http.HandlerFunc(handleRequest),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
				fmt.Printf("Incoming connection - SNI: %s\n", hello.ServerName)
				return nil, nil
			},
		},
	}

	fmt.Printf("HTTPS Server is running on https://%s\n", addr)
	log.Fatal(server.ListenAndServeTLS("", ""))
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("Received request from: %s\n", r.RemoteAddr)
	fmt.Fprintf(w, "Hello from (not) \"%s\"", r.TLS.ServerName)
}
