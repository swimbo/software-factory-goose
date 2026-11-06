//go:build linux

// Public, network-none fixture target for the pre-exec barrier; not a gateway.
package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
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

func namespaceCalls() (uintptr, uintptr, uintptr) {
	switch runtime.GOARCH {
	case "amd64":
		return 272, 308, 56
	case "arm64":
		return 97, 268, 220
	default:
		os.Exit(20)
		return 0, 0, 0
	}
}

func namespacesDenied() bool {
	unshare, setns, clone := namespaceCalls()
	_, _, unshareErr := syscall.RawSyscall(unshare, 0, 0, 0)
	_, _, setnsErr := syscall.RawSyscall(setns, ^uintptr(0), 0, 0)
	if unshareErr != syscall.EPERM || setnsErr != syscall.EPERM {
		return false
	}
	// CLONE_THREAD without CLONE_SIGHAND is invalid: these probes cannot
	// create children even if the namespace filter is missing.
	for _, flag := range []uintptr{0x20000, 0x2000000, 0x4000000, 0x8000000, 0x10000000, 0x20000000, 0x40000000} {
		_, _, errno := syscall.RawSyscall(clone, flag|0x10000, 0, 0)
		if errno != syscall.EPERM {
			return false
		}
	}
	_, _, clone3Err := syscall.RawSyscall(435, 0, 0, 0)
	return clone3Err == syscall.ENOSYS
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "probe-namespaces" {
		unshare, setns, clone := namespaceCalls()
		_, _, unshareErr := syscall.RawSyscall(unshare, 0, 0, 0)
		_, _, setnsErr := syscall.RawSyscall(setns, ^uintptr(0), 0, 0)
		if unshareErr != 0 || setnsErr != syscall.EBADF {
			os.Exit(24)
		}
		_, _, clone3Err := syscall.RawSyscall(435, 0, 0, 0)
		if clone3Err != syscall.EINVAL {
			os.Exit(27)
		}
		for _, flag := range []uintptr{0x20000, 0x2000000, 0x4000000, 0x8000000, 0x10000000, 0x20000000, 0x40000000} {
			_, _, errno := syscall.RawSyscall(clone, flag|0x10000, 0, 0)
			if errno != syscall.EINVAL {
				os.Exit(26)
			}
		}
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "probe-x32-alias" {
		syscall.RawSyscall(512, 0, 0, 0)
		os.Exit(23)
	}
	if len(os.Args) == 2 && os.Args[1] == "probe-child" {
		if !transferDenied(0) || !namespacesDenied() {
			os.Exit(11)
		}
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "hold-child" {
		if !transferDenied(0) || !namespacesDenied() {
			os.Exit(28)
		}
		fmt.Println("child-ready")
		io.Copy(io.Discard, os.Stdin)
		return
	}
	fd := flag.Int("socket-fd", -1, "")
	path := flag.String("socket-path", "", "")
	bootstrapFD := flag.Int("bootstrap-fd", -1, "")
	readyFD := flag.Int("cold-ready-fd", -1, "")
	flag.Parse()
	var coldReady map[string]any
	if *bootstrapFD >= 0 && *readyFD >= 0 {
		file := os.NewFile(uintptr(*bootstrapFD), "public-bootstrap")
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			os.Exit(31)
		}
		raw, err := io.ReadAll(io.LimitReader(file, 262145))
		file.Close()
		if err != nil || len(raw) > 262144 {
			os.Exit(31)
		}
		var config map[string]json.RawMessage
		if json.Unmarshal(raw, &config) != nil {
			os.Exit(31)
		}
		var allowance struct {
			Route struct {
				Review string `json:"review_sha256"`
			} `json:"route"`
		}
		if json.Unmarshal(config["allowance"], &allowance) != nil {
			os.Exit(31)
		}
		processStat, err := os.ReadFile("/proc/self/stat")
		if err != nil {
			os.Exit(31)
		}
		fields := strings.Fields(string(processStat)[strings.LastIndex(string(processStat), ")")+1:])
		ticks, err := strconv.ParseUint(fields[19], 10, 64)
		if err != nil {
			os.Exit(31)
		}
		coldReady = map[string]any{"schema": 1, "state": "cold-ready", "config_sha256": fmt.Sprintf("%x", sha256.Sum256(raw)),
			"pid": os.Getpid(), "start_ticks": ticks, "uid": os.Getuid(), "paid_ready": false, "review_sha256": allowance.Route.Review}
		for _, key := range []string{"launch_sha256", "grant_sha256", "scope_sha256", "socket_device", "socket_inode"} {
			coldReady[key] = config[key]
		}
		syscall.CloseOnExec(*readyFD)
	}
	value, _, dumpErr := syscall.Syscall6(syscall.SYS_PRCTL, 3, 0, 0, 0, 0, 0)
	if dumpErr != 0 || value != 1 {
		os.Exit(21)
	}
	if !transferDenied(*fd) {
		os.Exit(11)
	}
	if !namespacesDenied() {
		os.Exit(25)
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
	if !ok || unixAddr.Name != *path {
		os.Exit(3)
	}
	// Keep the listener private until the holding child has passed its probes.
	syscall.CloseOnExec(*fd)
	child := exec.Command("/proc/self/exe", "hold-child")
	if coldReady != nil {
		child.ExtraFiles = []*os.File{os.NewFile(uintptr(*fd), "public-descendant-socket")}
	}
	input, err := child.StdinPipe()
	if err != nil {
		os.Exit(29)
	}
	output, err := child.StdoutPipe()
	if err != nil || child.Start() != nil {
		os.Exit(29)
	}
	defer func() { input.Close(); child.Wait() }()
	if line, err := bufio.NewReader(output).ReadString('\n'); err != nil || line != "child-ready\n" {
		os.Exit(30)
	}
	if syscall.Listen(*fd, 1) != nil {
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
	if coldReady != nil {
		raw, err := json.Marshal(coldReady)
		if err != nil {
			os.Exit(31)
		}
		file := os.NewFile(uintptr(*readyFD), "public-cold-ready")
		if _, err = file.Write(append(raw, '\n')); err != nil {
			os.Exit(31)
		}
		file.Close()
	}
	conn, err := listener.Accept()
	if err != nil {
		os.Exit(5)
	}
	conn.Close()
}
