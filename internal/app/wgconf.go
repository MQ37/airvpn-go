package app

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"
)

// wgConfig is the subset of a wg-quick file that one AirVPN peer needs.
// Keys are kept hex-encoded because that is what the wireguard-go IPC wants.
type wgConfig struct {
	privateKey   string
	publicKey    string
	presharedKey string // optional
	addresses    []netip.Addr
	dns          []netip.Addr
	mtu          int
	endpoint     string // host:port
	allowedIPs   []string
	keepalive    int
}

// parseConfig reads a WireGuard config as produced by the AirVPN Config
// Generator. Unknown keys (Table, PostUp, ...) are ignored and never run.
func parseConfig(r io.Reader) (*wgConfig, error) {
	cfg := &wgConfig{mtu: 1320, keepalive: 15}
	section, peers := "", 0
	sc := bufio.NewScanner(r)
	for n := 1; sc.Scan(); n++ {
		line := sc.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") {
			section = strings.ToLower(line)
			switch section {
			case "[interface]":
			case "[peer]":
				if peers++; peers > 1 {
					return nil, fmt.Errorf("line %d: only one [Peer] is supported", n)
				}
			default:
				return nil, fmt.Errorf("line %d: unknown section %s", n, line)
			}
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("line %d: expected key = value", n)
		}
		k, v = strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(v)
		if err := cfg.set(section, k, v); err != nil {
			return nil, fmt.Errorf("line %d: %s: %w", n, k, err)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	switch {
	case cfg.privateKey == "":
		return nil, fmt.Errorf("missing [Interface] PrivateKey")
	case len(cfg.addresses) == 0:
		return nil, fmt.Errorf("missing [Interface] Address")
	case len(cfg.dns) == 0:
		return nil, fmt.Errorf("missing [Interface] DNS (needed to resolve names inside the tunnel)")
	case cfg.publicKey == "":
		return nil, fmt.Errorf("missing [Peer] PublicKey")
	case cfg.endpoint == "":
		return nil, fmt.Errorf("missing [Peer] Endpoint")
	}
	if len(cfg.allowedIPs) == 0 {
		cfg.allowedIPs = []string{"0.0.0.0/0", "::/0"}
	}
	return cfg, nil
}

func (c *wgConfig) set(section, k, v string) error {
	var err error
	switch section + " " + k {
	case "[interface] privatekey":
		c.privateKey, err = hexKey(v)
	case "[interface] address":
		for _, s := range splitList(v) {
			p, e := netip.ParsePrefix(s)
			if e != nil {
				return e
			}
			c.addresses = append(c.addresses, p.Addr())
		}
	case "[interface] dns":
		for _, s := range splitList(v) {
			a, e := netip.ParseAddr(s)
			if e != nil {
				return e
			}
			c.dns = append(c.dns, a)
		}
	case "[interface] mtu":
		if c.mtu, err = strconv.Atoi(v); err == nil && (c.mtu < 576 || c.mtu > 1500) {
			err = fmt.Errorf("out of range")
		}
	case "[peer] publickey":
		c.publicKey, err = hexKey(v)
	case "[peer] presharedkey":
		c.presharedKey, err = hexKey(v)
	case "[peer] endpoint":
		if _, _, err = splitHostPort(v); err == nil {
			c.endpoint = v
		}
	case "[peer] allowedips":
		for _, s := range splitList(v) {
			if _, e := netip.ParsePrefix(s); e != nil {
				return e
			}
			c.allowedIPs = append(c.allowedIPs, s)
		}
	case "[peer] persistentkeepalive":
		if c.keepalive, err = strconv.Atoi(v); err == nil && c.keepalive < 0 {
			err = fmt.Errorf("negative")
		}
	}
	return err
}

func splitList(v string) []string {
	var out []string
	for _, s := range strings.Split(v, ",") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// hexKey turns a base64 WireGuard key into the hex form the IPC expects. The
// value is never echoed in errors.
func hexKey(b64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil || len(raw) != 32 {
		return "", fmt.Errorf("not a base64 32-byte key")
	}
	return hex.EncodeToString(raw), nil
}
