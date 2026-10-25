package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// Saved credentials live in one file in the user's config directory, shared by
// every run of the tool on this system:
//
//	$AIRVPN_CONFIG_DIR, else $XDG_CONFIG_HOME/airvpn-go, else ~/.config/airvpn-go
//
// The file is plain JSON, owner-only (0600, directory 0700). It is NOT
// encrypted: its only protection is the file permissions. Saving is always the
// user's explicit answer to a prompt that defaults to no.

type savedCreds struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

func configDir() string {
	if d := os.Getenv("AIRVPN_CONFIG_DIR"); d != "" {
		return d
	}
	if d := os.Getenv("XDG_CONFIG_HOME"); d != "" {
		return filepath.Join(d, "airvpn-go")
	}
	if h := os.Getenv("HOME"); h != "" {
		return filepath.Join(h, ".config", "airvpn-go")
	}
	return ""
}

func credsPath() string {
	d := configDir()
	if d == "" {
		return ""
	}
	return filepath.Join(d, "credentials")
}

// shownPath is the path to tell the user; a launcher that runs us in a
// container passes the real host path in AIRVPN_CONFIG_SHOWN.
func shownPath() string {
	if p := os.Getenv("AIRVPN_CONFIG_SHOWN"); p != "" {
		return p
	}
	return credsPath()
}

// loadSaved returns the saved credentials, or nil if there are none. A file
// that other users can read is refused rather than trusted.
func loadSaved() (*savedCreds, error) {
	p := credsPath()
	if p == "" {
		return nil, nil
	}
	f, err := os.Open(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("saved credentials %s are readable by other users (mode %o): chmod 600 it, or run the forget command", shownPath(), st.Mode().Perm())
	}
	var s savedCreds
	if err := json.NewDecoder(io.LimitReader(f, 1<<16)).Decode(&s); err != nil || s.Login == "" || s.Password == "" {
		return nil, fmt.Errorf("saved credentials %s are unreadable: run the forget command", shownPath())
	}
	return &s, nil
}

// saveCreds writes the file atomically with owner-only permissions.
func saveCreds(s savedCreds) error {
	p := credsPath()
	if p == "" {
		return errors.New("no config directory (set AIRVPN_CONFIG_DIR)")
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(p), ".credentials-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), p)
}

// forgetCreds deletes the saved credentials; false if there were none.
func forgetCreds() (bool, error) {
	p := credsPath()
	if p == "" {
		return false, nil
	}
	err := os.Remove(p)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	return err == nil, err
}

// offerSave asks, after a successful login with typed credentials, whether to
// keep them. The default is no: only an explicit y/yes saves. Nothing is asked
// when they are already saved, came from the environment or a file, or there is
// no terminal.
func offerSave(c creds, canAsk bool, readLine func() (string, error), out io.Writer) {
	if !c.typed || c.fromSaved || !canAsk || credsPath() == "" {
		return
	}
	if saved, err := loadSaved(); err == nil && saved != nil && saved.Login == c.login && saved.Password == c.password {
		return
	}
	fmt.Fprintf(out, "\nSave these credentials on this machine for next time?\n"+
		"They would be stored UNENCRYPTED in %s (readable only by you).\nSave? [y/N]: ", shownPath())
	line, err := readLine()
	if err != nil {
		fmt.Fprintln(out)
		return
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		if err := saveCreds(savedCreds{c.login, c.password}); err != nil {
			fmt.Fprintf(out, "could not save: %v\n", err)
			return
		}
		fmt.Fprintf(out, "saved. Run \"airvpn-go forget\" to delete them.\n")
	default:
		fmt.Fprintln(out, "not saved.")
	}
}
