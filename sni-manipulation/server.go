package main

import (
	"fmt"
	"log"
	"net/http"
)

func main() {
	http.HandleFunc("/", handleRequest)
	fmt.Println("HTTPS Server is running on https://localhost:8443")
	log.Fatal(http.ListenAndServeTLS(":8443", "server.crt", "server.key", nil))
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	fmt.Println("Received request from:", r.RemoteAddr)
	fmt.Fprintf(w, "Hello, Client! This is the secure HTTPS server speaking.")
}
