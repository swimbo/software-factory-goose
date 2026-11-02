//go:build linux

// Public, network-none fixture target for the pre-exec barrier; not a gateway.
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"syscall"
)

func transferDenied(fd int) bool {
	pair, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		return false
	}
	defer syscall.Close(pair[0])
	defer syscall.Close(pair[1])
	_, err = syscall.SendmsgN(pair[0], []byte("x"), syscall.UnixRights(fd), nil, 0)
	return err == syscall.EPERM
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "probe-x32-alias" {
		syscall.RawSyscall(512, 0, 0, 0)
		os.Exit(23)
	}
	if len(os.Args) == 2 && os.Args[1] == "probe-child" {
		if !transferDenied(0) {
			os.Exit(11)
		}
		return
	}
	fd := flag.Int("socket-fd", -1, "")
	path := flag.String("socket-path", "", "")
	flag.Parse()
	if !transferDenied(*fd) {
		os.Exit(11)
	}
	var numbers []uintptr
	switch runtime.GOARCH {
	case "amd64":
		numbers = []uintptr{47, 299, 307, 425, 426, 427, 438}
	case "arm64":
		numbers = []uintptr{212, 243, 269, 425, 426, 427, 438}
	default:
		os.Exit(20)
	}
	for _, number := range numbers {
		_, _, errno := syscall.Syscall(number, ^uintptr(0), 0, 0)
		if errno != syscall.EPERM {
			os.Exit(16)
		}
	}
	if exec.Command("/proc/self/exe", "probe-child").Run() != nil {
		os.Exit(17)
	}
	if runtime.GOARCH == "amd64" {
		x32err := exec.Command("/proc/self/exe", "probe-x32-alias").Run()
		x32exit, ok := x32err.(*exec.ExitError)
		if !ok {
			os.Exit(18)
		}
		x32status, ok := x32exit.Sys().(syscall.WaitStatus)
		if !ok || !x32status.Signaled() || x32status.Signal() != syscall.SIGSYS {
			os.Exit(19)
		}
	}
	_, _, ioctlErr := syscall.Syscall(syscall.SYS_IOCTL, uintptr(*fd), 0, 0)
	if ioctlErr != syscall.EPERM {
		os.Exit(12)
	}
	// A filtered gateway must still be able to establish ordinary TCP streams.
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		os.Exit(13)
	}
	dial, err := net.Dial("tcp", tcp.Addr().String())
	if err != nil {
		os.Exit(14)
	}
	accepted, err := tcp.Accept()
	if err != nil {
		os.Exit(15)
	}
	accepted.Close()
	dial.Close()
	tcp.Close()
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
