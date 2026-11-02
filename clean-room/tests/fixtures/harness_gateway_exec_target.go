//go:build linux

// Public, network-none fixture target for the pre-exec barrier; not a gateway.
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"syscall"
)

func main() {
	fd := flag.Int("socket-fd", -1, "")
	path := flag.String("socket-path", "", "")
	flag.Parse()
	addr, err := syscall.Getsockname(*fd)
	if err != nil {
		os.Exit(2)
	}
	unixAddr, ok := addr.(*syscall.SockaddrUnix)
	if !ok || unixAddr.Name != *path || syscall.Listen(*fd, 1) != nil {
		os.Exit(3)
	}
	file := os.NewFile(uintptr(*fd), "fixture-socket")
	listener, err := net.FileListener(file)
	file.Close()
	if err != nil {
		os.Exit(4)
	}
	defer listener.Close()
	if unixListener, ok := listener.(*net.UnixListener); ok {
		unixListener.SetUnlinkOnClose(false)
	}
	fmt.Println("exec-ready")
	conn, err := listener.Accept()
	if err != nil {
		os.Exit(5)
	}
	conn.Close()
}
