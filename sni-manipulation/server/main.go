package main

import (
	"crypto/tls"
	"embed"
	"fmt"
	"log"
	"net/http"
)

//go:embed certs/server.crt certs/server.key
var certsFS embed.FS

func main() {
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
		Addr:    ":8443",
		Handler: http.HandlerFunc(handleRequest),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
				fmt.Printf("Incoming connection - SNI: %s\n", hello.ServerName)
				return nil, nil
			},
		},
	}

	fmt.Println("HTTPS Server is running on https://localhost:8443")
	log.Fatal(server.ListenAndServeTLS("", ""))
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	fmt.Printf("Received request from: %s\n", r.RemoteAddr)
	fmt.Fprintf(w, "Hello from (not) \"%s\"", r.TLS.ServerName)
}
