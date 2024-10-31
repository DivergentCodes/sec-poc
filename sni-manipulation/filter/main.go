/*
This is a TLS SNI filter that blocks or allows connections based on the SNI value.

Usage:

	./filter --domain-file <path> --default <allow|deny> [--port <port>]

It is designed to be used as a transparent proxy for TLS connections, listening on an
intermediate server's local port and forwarding to the original destination.

The domain list file contains one domain per line. Domains can use wildcards
(e.g. ".github.com" will match any github.com subdomain, but not github.com itself).

An iptables rules can be used to redirect the traffic to the local port.

	# Enable IP forwarding.
	sysctl -w net.ipv4.ip_forward=1

	# Configure firewall NAT rule.
	/sbin/iptables -t nat -A POSTROUTING -o "$(ip route | grep default | awk '{print $5}')" -j MASQUERADE

	# Configure firewall transparent proxying rules.
	/sbin/iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 3130;
*/
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
	"sync"
	"syscall"
	"time"
)

// TLSErrorCode represents a TLS alert code value
type TLSErrorCode byte

// fakeConn implements the minimal net.Conn interface needed for ClientHelloInfo
type fakeConn struct {
	net.Conn
}

const (
	// TLS Record Header Length
	TLSRecordHeaderLength = 5
	MaxTLSRecordLength    = 16384 + 2048
	// Socket option to get the original destination
	SO_ORIGINAL_DST = 80

	ActionAllowed = "Allowed"
	ActionBlocked = "Blocked"

	// TLS Alert Codes
	TLSCloseNotify            TLSErrorCode = 0
	TLSUnexpectedMessage      TLSErrorCode = 10
	TLSBadRecordMAC           TLSErrorCode = 20
	TLSDecryptionFailed       TLSErrorCode = 21 // deprecated
	TLSRecordOverflow         TLSErrorCode = 22
	TLSDecompressionFailure   TLSErrorCode = 30
	TLSHandshakeFailure       TLSErrorCode = 40
	TLSNoCertificate          TLSErrorCode = 41 // SSL3.0
	TLSBadCertificate         TLSErrorCode = 42
	TLSUnsupportedCertificate TLSErrorCode = 43
	TLSCertificateRevoked     TLSErrorCode = 44
	TLSCertificateExpired     TLSErrorCode = 45
	TLSCertificateUnknown     TLSErrorCode = 46
	TLSIllegalParameter       TLSErrorCode = 47
	TLSUnknownCA              TLSErrorCode = 48
	TLSAccessDenied           TLSErrorCode = 49
	TLSDecodeError            TLSErrorCode = 50
	TLSDecryptError           TLSErrorCode = 51
	TLSExportRestriction      TLSErrorCode = 60
	TLSProtocolVersion        TLSErrorCode = 70
	TLSInsufficientSecurity   TLSErrorCode = 71
	TLSInternalError          TLSErrorCode = 80
	TLSUserCanceled           TLSErrorCode = 90
	TLSNoRenegotiation        TLSErrorCode = 100
	TLSUnsupportedExtension   TLSErrorCode = 110

	certCacheExpiration = 1 * time.Hour // How long to cache successful validations
)

var (
	domainList      map[string]int
	defaultDeny     bool
	verifyCerts     bool
	certValidations = &certCache{
		validations: make(map[string][]string),
		lastChecked: make(map[string]time.Time),
	}
)

// Main entry point.
func main() {
	listenPort := flag.String("port", "3130", "Local port to listen on")
	domainFile := flag.String("domain-file", "", "File containing domain rules (one domain per line)")
	defaultAction := flag.String("default", "", "Default action (allow/deny) for unlisted domains")
	verifyFlag := flag.Bool("verify", false, "Verify server certificates match SNI")
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
	verifyCerts = *verifyFlag

	if verifyCerts {
		log.Printf("Certificate verification enabled")
	}

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

	// Start cache cleanup goroutine
	go func() {
		ticker := time.NewTicker(certCacheExpiration)
		defer ticker.Stop()

		for range ticker.C {
			certValidations.Lock()
			now := time.Now()

			// Remove expired entries
			for sni, lastChecked := range certValidations.lastChecked {
				if now.Sub(lastChecked) > certCacheExpiration {
					delete(certValidations.validations, sni)
					delete(certValidations.lastChecked, sni)
				}
			}

			certValidations.Unlock()
		}
	}()

	for {
		clientConn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}

		go handleConnection(clientConn)
	}
}

// Load domain list from file.
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

// Check if a domain is in the list.
func isDomainInList(domain string) (int, bool) {
	for pattern := range domainList {
		if isSubdomainMatch(domain, pattern) {
			domainList[pattern]++ // Increment counter for the matching pattern
			return domainList[pattern], true
		}
	}
	return 0, false
}

// Check if a domain matches a pattern (wildcard subdomain match).
func isSubdomainMatch(domain, pattern string) bool {
	// If pattern starts with ".", it's a wildcard subdomain match
	if strings.HasPrefix(pattern, ".") {
		// Remove the leading dot for comparison
		pattern = pattern[1:]
		// Domain must be longer than pattern (to have subdomain)
		// and must end with the pattern
		return len(domain) > len(pattern) && strings.HasSuffix(domain, pattern)
	}
	// Otherwise, exact match only
	return domain == pattern
}

// Get the original destination from the connection.
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

// Parse the ClientHello from a TLS record.
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

// ConnectionState returns a dummy tls.ConnectionState.
func (c *fakeConn) ConnectionState() tls.ConnectionState {
	return tls.ConnectionState{}
}

// Verify certificate
func verifyCertificate(address, sni string) error {
	// Check cache first using full address
	if certValidations.isValid(sni, address) {
		return nil
	}

	// Perform actual verification
	conf := &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: false,
	}

	dialer := &net.Dialer{
		Timeout: 5 * time.Second,
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", address, conf)
	if err != nil {
		return fmt.Errorf("TLS connection failed: %v", err)
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return fmt.Errorf("no certificates presented by server")
	}

	// Verify the certificate matches the SNI
	for _, cert := range certs {
		if err := cert.VerifyHostname(sni); err == nil {
			// Cache successful validation with full address
			certValidations.add(sni, address)
			return nil
		}
	}

	return fmt.Errorf("no valid certificate found for %s", sni)
}

// Handle a connection.
func handleConnection(clientConn net.Conn) {
	defer clientConn.Close()

	// Get original destination
	origDst, err := getOriginalDst(clientConn)
	if err != nil {
		log.Printf("Failed to get original destination: %v", err)
		return
	}

	// Peek at the first byte to check if it's TLS
	firstByte := make([]byte, 1)
	n, err := clientConn.Read(firstByte)
	if err != nil || n == 0 {
		allowConnection(clientConn, origDst, nil, nil)
		return
	}

	// If it's not a TLS handshake (0x16), allow the connection
	if firstByte[0] != 0x16 {
		allowConnection(clientConn, origDst, firstByte, nil)
		return
	}

	// Read the rest of the TLS record header
	header := make([]byte, TLSRecordHeaderLength-1) // -1 because we already read the first byte
	if _, err := io.ReadFull(clientConn, header); err != nil {
		allowConnection(clientConn, origDst, firstByte, nil)
		return
	}

	// Combine the first byte with the rest of the header
	fullHeader := append(firstByte, header...)

	// Verify TLS handshake
	if fullHeader[0] != 0x16 { // TLS Handshake
		allowConnection(clientConn, origDst, fullHeader, nil)
		return
	}

	// Get record length
	recordLen := uint16(fullHeader[3])<<8 | uint16(fullHeader[4])
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
	}

	count := 0
	isEmptySNI := clientHello == nil || clientHello.ServerName == ""

	if defaultDeny && isEmptySNI {
		logTLSConnection(clientConn, origDst, "", ActionBlocked, 0, "empty SNI")
		blockConnection(clientConn, TLSAccessDenied)
		return
	}

	if !isEmptySNI {
		if verifyCerts {
			if err := verifyCertificate(origDst, clientHello.ServerName); err != nil {
				logTLSConnection(clientConn, origDst, clientHello.ServerName, ActionBlocked, count, "invalid certificate")
				blockConnection(clientConn, TLSBadCertificate)
				return
			}
		}

		count, matched := isDomainInList(clientHello.ServerName)
		if defaultDeny && !matched {
			logTLSConnection(clientConn, origDst, clientHello.ServerName, ActionBlocked, count, "not in allow-list")
			blockConnection(clientConn, TLSAccessDenied)
			return
		}
		if !defaultDeny && matched {
			logTLSConnection(clientConn, origDst, clientHello.ServerName, ActionBlocked, count, "in block-list")
			blockConnection(clientConn, TLSAccessDenied)
			return
		}
	}

	// Allow
	logTLSConnection(clientConn, origDst, clientHello.ServerName, ActionAllowed, count, "")
	allowConnection(clientConn, origDst, fullHeader, record)
}

// Log a TLS connection.
func logTLSConnection(src net.Conn, dst string, sni string, action string, count int, msg string) {
	format := fmt.Sprintf(
		"%s TLS connection from [%s] to [%s] with SNI [%s]",
		action,
		src.RemoteAddr(),
		dst,
		sni,
	)

	if count > 0 {
		format += fmt.Sprintf(" (%d)", count)
	}

	if msg != "" {
		format += fmt.Sprintf(" (%s)", msg)
	}

	log.Print(format)
}

// Block a connection.
func blockConnection(clientConn net.Conn, tlsErrorCode TLSErrorCode) {
	alert := []byte{
		0x15,       // Alert protocol
		0x03, 0x03, // TLS version 1.2
		0x00, 0x02, // Length
		0x02, // Fatal alert
		byte(tlsErrorCode),
	}
	clientConn.Write(alert)
	clientConn.Close()
}

// Allow a connection.
func allowConnection(clientConn net.Conn, origDst string, header []byte, record []byte) {
	// Connect to original destination
	serverConn, err := net.Dial("tcp", origDst)
	if err != nil {
		log.Printf("Failed to connect to original destination %s: %v", origDst, err)
		return
	}
	defer serverConn.Close()

	if header != nil && record != nil {
		// Forward the handshake
		serverConn.Write(header)
		serverConn.Write(record)
	}

	// Continue proxying
	proxy(clientConn, serverConn)
}

// Proxy a connection.
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

type certCache struct {
	sync.RWMutex
	validations map[string][]string  // map[sni][]addresses (host:port)
	lastChecked map[string]time.Time // map[sni]lastValidationTime
}

func (c *certCache) isValid(sni, address string) bool {
	c.RLock()
	defer c.RUnlock()

	// Check if we have a cached validation
	if addresses, exists := c.validations[sni]; exists {
		// Check if the validation has expired
		if time.Since(c.lastChecked[sni]) > certCacheExpiration {
			return false
		}

		// Check if this address is in the validated list
		for _, addr := range addresses {
			if addr == address {
				return true
			}
		}
	}
	return false
}

func (c *certCache) add(sni, address string) {
	c.Lock()
	defer c.Unlock()

	// Check if we already have this SNI
	if addresses, exists := c.validations[sni]; exists {
		// Check if we already have this address
		for _, addr := range addresses {
			if addr == address {
				return
			}
		}
		// Add the new address to existing slice
		c.validations[sni] = append(addresses, address)
	} else {
		// Create new entry
		c.validations[sni] = []string{address}
	}

	// Update last checked time
	c.lastChecked[sni] = time.Now()
}
