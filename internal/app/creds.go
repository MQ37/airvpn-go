package app

import (
	"fmt"
	"os"
	"strings"
)

// creds is what a login attempt uses and where it came from.
type creds struct {
	login, password string
	typed           bool // at least the password was typed at a prompt
	fromSaved       bool // taken from the saved credentials file
}

// credentials returns the AirVPN login and password. Neither is needed on the
// command line: the login comes from -login or AIRVPN_LOGIN, the password from
// AIRVPN_PASSWORD or -password-file (never a flag: it would land in the process
// list and shell history). If no password was given, the saved credentials are
// used (see store.go). Whatever is still missing is asked for on the terminal,
// the password with echo off.
func credentials(login, passwordFile string) (creds, error) {
	if login == "" {
		login = os.Getenv("AIRVPN_LOGIN")
	}
	password := os.Getenv("AIRVPN_PASSWORD")
	if password == "" && passwordFile != "" {
		b, err := os.ReadFile(passwordFile)
		if err != nil {
			return creds{}, err
		}
		password = strings.TrimRight(string(b), "\r\n")
	}
	if password == "" {
		saved, err := loadSaved()
		if err != nil {
			return creds{}, err
		}
		if saved != nil && (login == "" || login == saved.Login) {
			fmt.Fprintf(os.Stderr, "using saved credentials for %s\n", saved.Login)
			return creds{login: saved.Login, password: saved.Password, fromSaved: true}, nil
		}
	}

	interactive := !noInput && isTerminal(os.Stdin)
	c := creds{login: login, password: password}
	if c.login == "" {
		if !interactive {
			return creds{}, fmt.Errorf("no login: use -login or AIRVPN_LOGIN, or run on a terminal to be asked")
		}
		fmt.Fprint(os.Stderr, "AirVPN login: ")
		line, err := readLine(os.Stdin)
		if err != nil {
			return creds{}, err
		}
		if c.login = strings.TrimSpace(line); c.login == "" {
			return creds{}, fmt.Errorf("empty login")
		}
		c.typed = true
	}
	if c.password == "" {
		if !interactive {
			return creds{}, fmt.Errorf("no password: use AIRVPN_PASSWORD or -password-file, or run on a terminal to be asked")
		}
		fmt.Fprint(os.Stderr, "AirVPN password: ")
		pw, err := readPassword(os.Stdin)
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return creds{}, err
		}
		if pw == "" {
			return creds{}, fmt.Errorf("empty password")
		}
		c.password, c.typed = pw, true
	}
	return c, nil
}

// readLine reads one line byte by byte, so nothing past the newline is
// consumed (a later prompt reads from the same file).
func readLine(f *os.File) (string, error) {
	var line []byte
	b := make([]byte, 1)
	for {
		n, err := f.Read(b)
		if n == 1 {
			if b[0] == '\n' {
				break
			}
			line = append(line, b[0])
		}
		if err != nil {
			if len(line) == 0 {
				return "", err
			}
			break
		}
	}
	return strings.TrimRight(string(line), "\r"), nil
}
