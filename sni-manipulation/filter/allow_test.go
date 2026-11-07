package main

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

func TestAllowConnectionForwardsBytesAlreadyRead(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	received := make(chan []byte, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			received <- nil
			return
		}
		defer conn.Close()
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, len("GET / HTTP/1.0\r\n"))
		io.ReadFull(conn, buf)
		received <- buf
	}()

	client, filterSide := net.Pipe()
	defer client.Close()
	go allowConnection(filterSide, listener.Addr().String(), []byte("G"), nil)

	client.Write([]byte("ET / HTTP/1.0\r\n"))

	select {
	case got := <-received:
		if want := []byte("GET / HTTP/1.0\r\n"); !bytes.Equal(got, want) {
			t.Errorf("destination received %q, want %q", got, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the destination")
	}
}
