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
	var hmac	string;
	if 3 != len(os.Args) {
		usage()
		os.Exit(2)
	}
	secret  = os.Args[1]
	message = os.Args[2]
	hmac = secret + message
	fmt.Printf("%v\n", hmac)
}
