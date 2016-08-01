package main

import (
	"os"
	"fmt"
)

func usage() {
	fmt.Fprintf(os.Stderr,
`Usage: %s <key> <message>

Prints an HMAC to stderr.
`	, os.Args[0])
}

func main() {
	var secret	string;
	var message	string;
	if 3 != len(os.Args) {
		usage()
		os.Exit(2)
	}
	secret  = os.Args[1]
	message = os.Args[2]
	fmt.Printf("Key: '%s' (%d bytes)\nMsg: '%s' (%d bytes)\nHash: %x\nHMAC: %x\n",
		secret, len([]byte(secret)),
		message, len([]byte(message)),
		TEST_SHA256([]byte(message)),
		HMAC([]byte(secret), []byte(message)))
}
