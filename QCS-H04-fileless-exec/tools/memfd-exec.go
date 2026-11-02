// memfd-exec — fileless-execution demo for lab QCS-H04.
// Copies /bin/true into an anonymous memfd and execs it via /proc/self/fd —
// the binary never touches the filesystem. Pure syscalls, builds static:
//
//	CGO_ENABLED=0 go build -o memfd-exec tools/memfd-exec.go
package main

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

const sysMemfdCreate = 319 // x86_64 memfd_create

func main() {
	name, _ := syscall.BytePtrFromString("citi-h04-memfd")
	fd, _, errno := syscall.RawSyscall(sysMemfdCreate, uintptr(unsafe.Pointer(name)), 0, 0)
	if errno != 0 {
		fmt.Fprintln(os.Stderr, "memfd_create:", errno)
		os.Exit(1)
	}

	// busybox resolves the applet from argv[0]; invoke it explicitly.
	data, err := os.ReadFile("/bin/busybox")
	if err != nil {
		fmt.Fprintln(os.Stderr, "read busybox:", err)
		os.Exit(1)
	}
	if _, err := syscall.Write(int(fd), data); err != nil {
		fmt.Fprintln(os.Stderr, "write memfd:", err)
		os.Exit(1)
	}

	execPath := fmt.Sprintf("/proc/self/fd/%d", fd)
	err = syscall.Exec(execPath, []string{"busybox", "echo", "CITI-H04-MEMFD-PAYLOAD-RAN"}, os.Environ())
	if err != nil {
		fmt.Fprintln(os.Stderr, "exec:", err)
		os.Exit(1)
	}
}
