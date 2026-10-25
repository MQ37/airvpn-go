//go:build !linux

package app

import (
	"errors"
	"os"
)

func isTerminal(*os.File) bool { return false }

func readPassword(*os.File) (string, error) {
	return "", errors.New("no hidden prompt on this OS: use AIRVPN_PASSWORD or -password-file")
}
