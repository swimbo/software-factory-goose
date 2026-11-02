//go:build linux

// Public fixture-only wrapper. It does not authorize or start a production gateway.
package main

import (
	"os"
	"syscall"
)

func main() {
	target := "/test.real"
	wallet := os.Getenv("SFACTORY_WALLET_JOIN_FIXTURE") == "1"
	if wallet {
		target = "/opt/wallet-gateway-real"
	}
	args := append([]string{target}, os.Args[1:]...)
	if wallet || os.Getenv("SFACTORY_ACTUAL_ROLE") == "gateway" {
		args = append([]string{"/usr/local/bin/python3", "-I", "-B", "/opt/filter_launcher.py"}, args...)
		_ = syscall.Exec(args[0], args, os.Environ())
	} else {
		_ = syscall.Exec(args[0], args, os.Environ())
	}
	os.Exit(125)
}
