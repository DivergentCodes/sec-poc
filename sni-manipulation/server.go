package main

import (
	"crypto/tls"
	"embed"
	"fmt"
	"log"
	"net/http"
)

//go:embed dist/certs/server.crt dist/certs/server.key
var certsFS embed.FS

func main() {
	http.HandleFunc("/", handleRequest)
	fmt.Println("HTTPS Server is running on https://localhost:8443")

	certPEMBytes, err := certsFS.ReadFile("dist/certs/server.crt")
	if err != nil {
		log.Fatal(err)
	}
	keyPEMBytes, err := certsFS.ReadFile("dist/certs/server.key")
	if err != nil {
		log.Fatal(err)
	}

	cert, err := tls.X509KeyPair(certPEMBytes, keyPEMBytes)
	if err != nil {
		log.Fatal(err)
	}

	server := &http.Server{
		Addr:    ":8443",
		Handler: nil, // Use the default ServeMux
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
		},
	}

	log.Fatal(server.ListenAndServeTLS("", ""))
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Received request from:", r.RemoteAddr)
	fmt.Fprintf(w, "Hello, Client! This is the secure HTTPS server speaking.")
}
