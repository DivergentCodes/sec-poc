package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"syscall"
)

const (
	TLSRecordHeaderLength = 5
	MaxTLSRecordLength    = 16384 + 2048
	SO_ORIGINAL_DST       = 80
)

var (
	domainList  map[string]int
	defaultDeny bool
)

func main() {
	listenPort := flag.String("port", "3130", "Local port to listen on")
	domainFile := flag.String("domain-file", "", "File containing domain rules (one domain per line)")
	defaultAction := flag.String("default", "", "Default action (allow/deny) for unlisted domains")
	flag.Parse()

	// Check if required arguments are provided
	if *domainFile == "" {
		log.Fatal("--domain-file argument is required")
	}
	if *defaultAction == "" {
		log.Fatal("--default argument is required")
	}
	if *defaultAction != "allow" && *defaultAction != "deny" {
		log.Fatal("--default argument must be either 'allow' or 'deny'")
	}

	// Initialize domain filtering
	domainList = make(map[string]int)
	defaultDeny = *defaultAction == "deny"

	// Load domain list from file
	if err := loadDomainList(*domainFile); err != nil {
		log.Fatalf("Failed to load domain list: %v", err)
	}

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

	// Get original destination
	origDst, err := getOriginalDst(clientConn)
	if err != nil {
		log.Printf("Failed to get original destination: %v", err)
		return
	}

	// Connect to original destination
	serverConn, err := net.Dial("tcp", origDst)
	if err != nil {
		log.Printf("Failed to connect to original destination %s: %v", origDst, err)
		return
	}
	defer serverConn.Close()

	// Read TLS record header
	header := make([]byte, TLSRecordHeaderLength)
	if _, err := io.ReadFull(clientConn, header); err != nil {
		log.Printf("Failed to read TLS header: %v", err)
		return
	}

	// Verify TLS handshake
	if header[0] != 0x16 { // TLS Handshake
		log.Printf("Not a TLS handshake")
		serverConn.Write(header)
		proxy(clientConn, serverConn)
		return
	}

	// Get record length
	recordLen := uint16(header[3])<<8 | uint16(header[4])
	if recordLen > MaxTLSRecordLength {
		log.Printf("TLS record too large: %d", recordLen)
		return
	}

	// Read the full handshake
	record := make([]byte, recordLen)
	if _, err := io.ReadFull(clientConn, record); err != nil {
		log.Printf("Failed to read handshake record: %v", err)
		return
	}

	// Parse ClientHello using crypto/tls
	clientHello, err := parseClientHello(record)
	if err != nil {
		log.Printf("Failed to parse ClientHello: %v", err)
	} else if clientHello != nil {
		log.Printf(
			"TLS connection from %s to %s - SNI: %s",
			clientConn.RemoteAddr(),
			origDst,
			clientHello.ServerName,
		)
	}

	if defaultDeny {
		// Default deny
		if clientHello == nil || clientHello.ServerName == "" {
			log.Printf("Blocked: no SNI")
		} else {
			_, exists := domainList[clientHello.ServerName]
			if exists {
				domainList[clientHello.ServerName]++
				log.Printf("Allowed: %s (count: %d)", clientHello.ServerName, domainList[clientHello.ServerName])
			} else {
				log.Printf("Blocked: %s", clientHello.ServerName)
			}
		}
	} else {
		// Default allow
		if clientHello == nil || clientHello.ServerName == "" {
			log.Printf("Allowed: no SNI")
		} else {
			_, exists := domainList[clientHello.ServerName]
			if exists {
				domainList[clientHello.ServerName]++
				log.Printf("Blocked: %s (count: %d)", clientHello.ServerName, domainList[clientHello.ServerName])
			} else {
				log.Printf("Allowed: %s", clientHello.ServerName)
			}
		}
	}

	// Forward the handshake
	serverConn.Write(header)
	serverConn.Write(record)

	// Continue proxying
	proxy(clientConn, serverConn)
}

func parseClientHello(record []byte) (*tls.ClientHelloInfo, error) {
	hello := &tls.ClientHelloInfo{
		Conn: &fakeConn{},
	}

	// Skip handshake header (1 byte type + 3 bytes length)
	if len(record) < 4 {
		return nil, fmt.Errorf("record too short")
	}
	reader := bytes.NewReader(record[4:])

	// Skip client version
	if _, err := reader.Seek(2, io.SeekCurrent); err != nil {
		return nil, err
	}

	// Skip random (32 bytes)
	if _, err := reader.Seek(32, io.SeekCurrent); err != nil {
		return nil, err
	}

	// Skip session id
	sessionIDLen, err := reader.ReadByte()
	if err != nil {
		return nil, err
	}
	if _, err := reader.Seek(int64(sessionIDLen), io.SeekCurrent); err != nil {
		return nil, err
	}

	// Skip cipher suites
	var cipherSuitesLen uint16
	if err := binary.Read(reader, binary.BigEndian, &cipherSuitesLen); err != nil {
		return nil, err
	}
	if _, err := reader.Seek(int64(cipherSuitesLen), io.SeekCurrent); err != nil {
		return nil, err
	}

	// Skip compression methods
	compressionMethodsLen, err := reader.ReadByte()
	if err != nil {
		return nil, err
	}
	if _, err := reader.Seek(int64(compressionMethodsLen), io.SeekCurrent); err != nil {
		return nil, err
	}

	// Read extensions length
	var extensionsLen uint16
	if err := binary.Read(reader, binary.BigEndian, &extensionsLen); err != nil {
		return nil, err
	}

	// Parse extensions
	extensionsData := make([]byte, extensionsLen)
	if _, err := io.ReadFull(reader, extensionsData); err != nil {
		return nil, err
	}

	// Find SNI extension
	extReader := bytes.NewReader(extensionsData)
	for extReader.Len() > 0 {
		var extType, extLen uint16
		if err := binary.Read(extReader, binary.BigEndian, &extType); err != nil {
			return nil, err
		}
		if err := binary.Read(extReader, binary.BigEndian, &extLen); err != nil {
			return nil, err
		}

		if extType == 0 { // SNI extension
			// Skip list length
			if _, err := extReader.Seek(2, io.SeekCurrent); err != nil {
				return nil, err
			}
			// Skip name type
			if _, err := extReader.Seek(1, io.SeekCurrent); err != nil {
				return nil, err
			}
			// Read server name length
			var nameLen uint16
			if err := binary.Read(extReader, binary.BigEndian, &nameLen); err != nil {
				return nil, err
			}
			serverName := make([]byte, nameLen)
			if _, err := io.ReadFull(extReader, serverName); err != nil {
				return nil, err
			}
			hello.ServerName = string(serverName)
			break
		}

		if _, err := extReader.Seek(int64(extLen), io.SeekCurrent); err != nil {
			return nil, err
		}
	}

	return hello, nil
}

// fakeConn implements the minimal net.Conn interface needed for ClientHelloInfo
type fakeConn struct {
	net.Conn
}

func (c *fakeConn) ConnectionState() tls.ConnectionState {
	return tls.ConnectionState{}
}

func proxy(client, server net.Conn) {
	done := make(chan bool, 2)
	copy := func(dst, src net.Conn) {
		io.Copy(dst, src)
		done <- true
	}
	go copy(server, client)
	go copy(client, server)
	<-done
}

func loadDomainList(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		domain := strings.TrimSpace(scanner.Text())
		if domain == "" || strings.HasPrefix(domain, "#") {
			continue
		}

		domainList[domain] = 0
		if defaultDeny {
			log.Printf("Allowing domain: %s", domain)
		} else {
			log.Printf("Blocking domain: %s", domain)
		}
	}

	return scanner.Err()
}
