package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"syscall"
)

const (
	TLSRecordHeaderLength = 5
	MaxTLSRecordLength    = 16384 + 2048
	SO_ORIGINAL_DST       = 80 // Linux socket option to get original destination
)

func main() {
	listenPort := flag.String("port", "3130", "Local port to listen on")
	flag.Parse()

	listener, err := net.Listen("tcp", ":"+*listenPort)
	if err != nil {
		log.Fatalf("Failed to start listener: %v", err)
	}
	defer listener.Close()

	log.Printf("TLS filter listening on port %s", *listenPort)

	for {
		clientConn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}

		go handleConnection(clientConn)
	}
}

func getOriginalDst(conn net.Conn) (string, error) {
	// Get the underlying TCP connection
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return "", fmt.Errorf("not a TCP connection")
	}

	// Get the file descriptor
	file, err := tcpConn.File()
	if err != nil {
		return "", err
	}
	defer file.Close()

	// Get original destination using SO_ORIGINAL_DST
	fd := int(file.Fd())
	addr, err := syscall.GetsockoptIPv6Mreq(fd, syscall.IPPROTO_IP, SO_ORIGINAL_DST)
	if err != nil {
		return "", err
	}

	// Convert the raw address to a string
	dstIP := net.IPv4(addr.Multiaddr[4], addr.Multiaddr[5], addr.Multiaddr[6], addr.Multiaddr[7])
	dstPort := uint16(addr.Multiaddr[2])<<8 + uint16(addr.Multiaddr[3])

	return fmt.Sprintf("%s:%d", dstIP.String(), dstPort), nil
}

func handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	// Get the original destination from the redirected connection
	origDst, err := getOriginalDst(clientConn)
	if err != nil {
		log.Printf("Failed to get original destination: %v", err)
		return
	}

	// Log the connection details
	log.Printf("Connection from %s to %s", clientConn.RemoteAddr(), origDst)

	// Connect to the original destination
	serverConn, err := net.Dial("tcp", origDst)
	if err != nil {
		log.Printf("Failed to connect to original destination %s: %v", origDst, err)
		return
	}
	defer serverConn.Close()

	// Buffer for TLS record header
	headerBuf := make([]byte, TLSRecordHeaderLength)

	// Read the TLS record header
	_, err = io.ReadFull(clientConn, headerBuf)
	if err != nil {
		log.Printf("Failed to read TLS header: %v", err)
		return
	}

	// Verify it's a TLS handshake
	if headerBuf[0] != 0x16 {
		log.Printf("Not a TLS handshake from %s", clientConn.RemoteAddr())
		return
	}

	// Get handshake message length
	recordLength := int(binary.BigEndian.Uint16(headerBuf[3:5]))
	if recordLength > MaxTLSRecordLength {
		log.Printf("TLS record too large from %s: %d", clientConn.RemoteAddr(), recordLength)
		return
	}

	// Read the handshake message
	handshakeBuf := make([]byte, recordLength)
	_, err = io.ReadFull(clientConn, handshakeBuf)
	if err != nil {
		log.Printf("Failed to read handshake: %v", err)
		return
	}

	// Extract and log SNI
	sni := extractSNI(handshakeBuf)
	if sni != "" {
		log.Printf("Connection from %s to %s - SNI: %s",
			clientConn.RemoteAddr(),
			origDst,
			sni)
	}

	// Forward the initial TLS handshake
	serverConn.Write(headerBuf)
	serverConn.Write(handshakeBuf)

	// Start bidirectional forwarding
	go io.Copy(serverConn, clientConn)
	io.Copy(clientConn, serverConn)
}

func extractSNI(data []byte) string {
	if len(data) < 2 {
		return ""
	}

	// Skip handshake type and length
	pos := 2

	// Skip protocol version
	pos += 2

	// Skip random
	pos += 32

	// Skip session ID
	if pos+1 > len(data) {
		return ""
	}
	sessionIDLength := int(data[pos])
	pos += 1 + sessionIDLength

	// Skip cipher suites
	if pos+2 > len(data) {
		return ""
	}
	cipherSuitesLength := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2 + cipherSuitesLength

	// Skip compression methods
	if pos+1 > len(data) {
		return ""
	}
	compressionMethodsLength := int(data[pos])
	pos += 1 + compressionMethodsLength

	// Check for extensions
	if pos+2 > len(data) {
		return ""
	}
	extensionsLength := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2

	// Parse extensions
	end := pos + extensionsLength
	for pos+4 <= end {
		extensionType := binary.BigEndian.Uint16(data[pos : pos+2])
		extensionLength := int(binary.BigEndian.Uint16(data[pos+2 : pos+4]))
		pos += 4

		if extensionType == 0 { // Server Name Indication extension
			if pos+2 > len(data) {
				return ""
			}

			// Skip server name list length
			pos += 2

			if pos+1 > len(data) {
				return ""
			}

			// Skip name type
			pos += 1

			if pos+2 > len(data) {
				return ""
			}

			nameLength := int(binary.BigEndian.Uint16(data[pos : pos+2]))
			pos += 2

			if pos+nameLength > len(data) {
				return ""
			}

			return string(data[pos : pos+nameLength])
		}

		pos += extensionLength
	}

	return ""
}
