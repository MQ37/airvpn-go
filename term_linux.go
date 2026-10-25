package main

import (
	"os"
	"syscall"
	"unsafe"
)

func ioctl(fd uintptr, req uintptr, t *syscall.Termios) error {
	_, _, e := syscall.Syscall(syscall.SYS_IOCTL, fd, req, uintptr(unsafe.Pointer(t)))
	if e != 0 {
		return e
	}
	return nil
}

func isTerminal(f *os.File) bool {
	var t syscall.Termios
	return ioctl(f.Fd(), syscall.TCGETS, &t) == nil
}

// readPassword reads one line from the terminal f with echo switched off.
func readPassword(f *os.File) (string, error) {
	var old syscall.Termios
	if err := ioctl(f.Fd(), syscall.TCGETS, &old); err != nil {
		return "", err
	}
	quiet := old
	quiet.Lflag &^= syscall.ECHO
	if err := ioctl(f.Fd(), syscall.TCSETS, &quiet); err != nil {
		return "", err
	}
	defer ioctl(f.Fd(), syscall.TCSETS, &old)
	return readLine(f)
}
