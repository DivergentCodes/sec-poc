package main

import "testing"

func TestVerifyHostResolvesToDst(t *testing.T) {
	if err := verifyHostResolvesToDst("localhost", "127.0.0.1:80"); err != nil {
		t.Errorf("localhost to 127.0.0.1: %v", err)
	}
	if err := verifyHostResolvesToDst("localhost", "192.0.2.1:80"); err == nil {
		t.Error("localhost to 192.0.2.1 was accepted")
	}
}
