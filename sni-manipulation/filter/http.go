package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"time"
)

const httpHeaderTimeout = 10 * time.Second

// Listen for plaintext HTTP redirected from port 80 and filter it by Host header.
func serveHTTP(listenPort string) {
	listener, err := net.Listen("tcp", ":"+listenPort)
	if err != nil {
		log.Fatalf("Failed to start HTTP listener: %v", err)
	}
	defer listener.Close()

	log.Printf("HTTP filter listening on port %s", listenPort)

	for {
		clientConn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept HTTP connection: %v", err)
			continue
		}

		go handleHTTPConnection(clientConn)
	}
}

// Handle a plaintext HTTP connection. Only the first request's Host header is
// checked, the same per-connection decision the TLS filter makes on the SNI.
func handleHTTPConnection(clientConn net.Conn) {
	defer clientConn.Close()

	origDst, err := getOriginalDst(clientConn)
	if err != nil {
		log.Printf("Failed to get original destination: %v", err)
		return
	}

	// Record every byte read from the client so the request can be replayed to
	// the destination unchanged, including anything buffered past the headers.
	var consumed bytes.Buffer
	reader := bufio.NewReader(io.TeeReader(clientConn, &consumed))

	clientConn.SetReadDeadline(time.Now().Add(httpHeaderTimeout))
	req, err := http.ReadRequest(reader)
	clientConn.SetReadDeadline(time.Time{})
	if err != nil {
		logHTTPConnection(clientConn, origDst, "", ActionBlocked, 0, "not an HTTP request")
		return
	}

	host := req.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	if host == "" {
		if defaultDeny {
			logHTTPConnection(clientConn, origDst, "", ActionBlocked, 0, "empty Host")
			blockHTTPConnection(clientConn)
			return
		}
	} else {
		count, matched := isDomainInList(host)
		if defaultDeny && !matched {
			logHTTPConnection(clientConn, origDst, host, ActionBlocked, count, "not in allow-list")
			blockHTTPConnection(clientConn)
			return
		}
		if !defaultDeny && matched {
			logHTTPConnection(clientConn, origDst, host, ActionBlocked, count, "in block-list")
			blockHTTPConnection(clientConn)
			return
		}

		// Plaintext has no certificate to check, so the closest equivalent is
		// requiring the destination to be an address the Host name resolves to.
		if verifyCerts {
			if err := verifyHostResolvesToDst(host, origDst); err != nil {
				logHTTPConnection(clientConn, origDst, host, ActionBlocked, count, err.Error())
				blockHTTPConnection(clientConn)
				return
			}
		}
	}

	logHTTPConnection(clientConn, origDst, host, ActionAllowed, 0, "")

	serverConn, err := net.Dial("tcp", origDst)
	if err != nil {
		log.Printf("Failed to connect to original destination %s: %v", origDst, err)
		return
	}
	defer serverConn.Close()

	if _, err := serverConn.Write(consumed.Bytes()); err != nil {
		log.Printf("Failed to forward HTTP request to %s: %v", origDst, err)
		return
	}

	proxy(clientConn, serverConn)
}

// Check that the original destination is one of the addresses the Host resolves to.
// DNS answers that rotate faster than the client's own lookup can cause false blocks.
func verifyHostResolvesToDst(host, origDst string) error {
	dstIP, _, err := net.SplitHostPort(origDst)
	if err != nil {
		return fmt.Errorf("invalid destination: %v", err)
	}

	addrs, err := net.LookupHost(host)
	if err != nil {
		return fmt.Errorf("host lookup failed: %v", err)
	}

	for _, addr := range addrs {
		if addr == dstIP {
			return nil
		}
	}
	return fmt.Errorf("destination not in %s addresses", host)
}

// Log an HTTP connection.
func logHTTPConnection(src net.Conn, dst string, host string, action string, count int, msg string) {
	format := fmt.Sprintf(
		"%s HTTP connection from [%s] to [%s] with Host [%s]",
		action,
		src.RemoteAddr(),
		dst,
		host,
	)

	if count > 0 {
		format += fmt.Sprintf(" (%d)", count)
	}

	if msg != "" {
		format += fmt.Sprintf(" (%s)", msg)
	}

	log.Print(format)
}

// Block an HTTP connection with a 403.
func blockHTTPConnection(clientConn net.Conn) {
	io.WriteString(clientConn, "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
}
