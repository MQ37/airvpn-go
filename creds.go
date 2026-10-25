package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// credentials returns the AirVPN login and password. The password is never a
// command-line flag (it would land in the process list and shell history):
// AIRVPN_PASSWORD, then -password-file, then a hidden prompt on the terminal.
func credentials(login, passwordFile string) (string, string, error) {
	if login == "" {
		login = os.Getenv("AIRVPN_LOGIN")
	}
	interactive := isTerminal(os.Stdin)
	if login == "" {
		if !interactive {
			return "", "", fmt.Errorf("no login: use -login or AIRVPN_LOGIN")
		}
		fmt.Fprint(os.Stderr, "AirVPN login: ")
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil {
			return "", "", err
		}
		login = strings.TrimSpace(line)
	}
	if p := os.Getenv("AIRVPN_PASSWORD"); p != "" {
		return login, p, nil
	}
	if passwordFile != "" {
		b, err := os.ReadFile(passwordFile)
		if err != nil {
			return "", "", err
		}
		return login, strings.TrimRight(string(b), "\r\n"), nil
	}
	if !interactive {
		return "", "", fmt.Errorf("no password: use AIRVPN_PASSWORD, -password-file, or run on a terminal")
	}
	fmt.Fprint(os.Stderr, "AirVPN password: ")
	pw, err := readPassword(os.Stdin)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", "", err
	}
	return login, pw, nil
}
